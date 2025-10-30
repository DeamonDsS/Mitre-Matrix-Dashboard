# backend/ml/train/fetch_es_data.py
import asyncio
from elasticsearch import AsyncElasticsearch
import pandas as pd
import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from datetime import datetime
import json

# Global ES client
es: Optional[AsyncElasticsearch] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager for ES client"""
    global es
    ES_URL = os.getenv("ES_URL", "http://localhost:9200")
    ES_USER = os.getenv("ES_USER", "")
    ES_PASS = os.getenv("ES_PASS", "")
    
    try:
        if ES_USER and ES_PASS:
            es = AsyncElasticsearch([ES_URL], basic_auth=(ES_USER, ES_PASS))
        else:
            es = AsyncElasticsearch([ES_URL])
        
        # Verify connection
        info = await es.info()
        print(f"✅ Elasticsearch client connected: {info['version']['number']}")
        
        yield
    finally:
        # Shutdown - Close ES client properly
        if es:
            await es.close()
            print("✅ Elasticsearch client closed")


async def debug_es_connection(client: AsyncElasticsearch, index: str):
    """Debug function to check ES connection and index"""
    print("\n" + "="*60)
    print("🔍 DEBUGGING ELASTICSEARCH CONNECTION")
    print("="*60)
    
    try:
        # 1. Check cluster health
        health = await client.cluster.health()
        print(f"\n✅ Cluster Status: {health['status']}")
        print(f"   Nodes: {health['number_of_nodes']}")
        print(f"   Active Shards: {health['active_shards']}")
        
        # 2. List all indices matching pattern
        print(f"\n🔍 Searching for indices matching: {index}")
        indices = await client.cat.indices(index=index, format="json")
        
        if indices:
            print(f"   Found {len(indices)} matching indices:")
            for idx in indices:
                print(f"   - {idx['index']}: {idx['docs.count']} docs, {idx['store.size']}")
        else:
            print("   ⚠️  No indices found matching pattern!")
            
            # Try to list ALL indices
            print("\n   Listing ALL indices:")
            all_indices = await client.cat.indices(format="json")
            for idx in all_indices[:10]:  # Show first 10
                print(f"   - {idx['index']}")
            if len(all_indices) > 10:
                print(f"   ... and {len(all_indices) - 10} more")
        
        # 3. Check index stats
        try:
            stats = await client.indices.stats(index=index)
            total_docs = stats['_all']['primaries']['docs']['count']
            print(f"\n📊 Total documents in {index}: {total_docs}")
        except Exception as e:
            print(f"\n⚠️  Could not get index stats: {str(e)}")
        
        # 4. Try a simple match_all query
        print(f"\n🔍 Testing match_all query (limit 1)...")
        test_resp = await client.search(
            index=index,
            body={
                "query": {"match_all": {}},
                "size": 1
            }
        )
        test_total = test_resp["hits"]["total"]["value"]
        print(f"   Match all query found: {test_total} documents")
        
        if test_total > 0:
            sample_doc = test_resp["hits"]["hits"][0]["_source"]
            print(f"\n📄 Sample document fields:")
            for key in list(sample_doc.keys())[:10]:
                print(f"   - {key}")
            
            # Check if @timestamp exists
            if "@timestamp" in sample_doc:
                print(f"\n✅ @timestamp field exists: {sample_doc['@timestamp']}")
            else:
                print("\n⚠️  @timestamp field NOT found! Available time fields:")
                time_fields = [k for k in sample_doc.keys() if 'time' in k.lower() or 'date' in k.lower()]
                for field in time_fields:
                    print(f"   - {field}")
        
        # 5. Try the time range query
        print(f"\n🔍 Testing time range query (now-7d to now)...")
        range_resp = await client.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": "now-7d/d", "lte": "now"}}}
                        ]
                    }
                },
                "size": 0  # Just get count
            }
        )
        range_total = range_resp["hits"]["total"]["value"]
        print(f"   Time range query found: {range_total} documents")
        
        # 6. Try without time filter
        print(f"\n🔍 Testing query WITHOUT time filter...")
        no_filter_resp = await client.search(
            index=index,
            body={
                "query": {"match_all": {}},
                "size": 0
            }
        )
        no_filter_total = no_filter_resp["hits"]["total"]["value"]
        print(f"   Query without filter found: {no_filter_total} documents")
        
    except Exception as e:
        print(f"\n❌ Debug error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("="*60 + "\n")


async def fetch_logs_from_es(
    index: str = None,
    days_back: int = 7,
    max_size: int = 1000,
    output_path: str = "ml/data/logs.csv",
    debug: bool = True
) -> pd.DataFrame:
    """
    Fetch logs from Elasticsearch and save to CSV
    
    Args:
        index: ES index pattern (defaults to env var or winlogbeats-9.1.5)
        days_back: Number of days to look back
        max_size: Maximum number of documents to fetch
        output_path: Path to save the CSV file
        debug: Enable debug mode
        
    Returns:
        DataFrame containing the fetched logs
    """
    # Get configuration from environment or use defaults
    ES_URL = os.getenv("ES_URL", "http://localhost:9200")
    ES_USER = os.getenv("ES_USER", "")
    ES_PASS = os.getenv("ES_PASS", "")
    ES_INDEX = index or os.getenv("ES_INDEX_NAME", "winlogbeat-*")
    
    # Create ES client
    try:
        if ES_USER and ES_PASS:
            client = AsyncElasticsearch([ES_URL], basic_auth=(ES_USER, ES_PASS))
        else:
            client = AsyncElasticsearch([ES_URL])
        
        print(f"🔍 Fetching logs from index: {ES_INDEX}")
        print(f"📅 Time range: last {days_back} days")
        print(f"🔗 ES URL: {ES_URL}")
        
        # Run debug if enabled
        if debug:
            await debug_es_connection(client, ES_INDEX)
        
        # Build query - try match_all first if time range fails
        query = {
            "match_all": {}
        }
        
        # Try with time filter first
        time_query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{days_back}d/d", "lte": "now"}}}
                ]
            }
        }
        
        # Fetch data
        print(f"\n📥 Fetching up to {max_size} documents...")
        
        if max_size > 10000:
            hits = await _fetch_with_scroll(client, ES_INDEX, time_query, max_size)
        else:
            # Try with time filter
            resp = await client.search(index=ES_INDEX, size=max_size, query=time_query)
            total_with_time = resp["hits"]["total"]["value"]
            
            if total_with_time == 0:
                print("⚠️  No results with time filter, trying without filter...")
                resp = await client.search(index=ES_INDEX, size=max_size, query=query)
                total_with_time = resp["hits"]["total"]["value"]
                print(f"📊 Found {total_with_time} documents without time filter")
            
            hits = [h["_source"] for h in resp["hits"]["hits"]]
            total = resp["hits"]["total"]["value"]
            print(f"📊 Found {total} total documents, fetched {len(hits)}")
        
        if not hits:
            print("⚠️  No logs found matching the criteria")
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(hits)
        
        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Save to CSV
        df.to_csv(output_file, index=False)
        print(f"✅ Saved {len(df)} logs to {output_path}")
        print(f"📋 Columns ({len(df.columns)}): {', '.join(df.columns.tolist()[:10])}{'...' if len(df.columns) > 10 else ''}")
        
        # Show data info
        if not df.empty:
            print(f"\n📊 DataFrame Info:")
            print(f"   Shape: {df.shape}")
            if '@timestamp' in df.columns:
                print(f"   Time range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")
        
        return df
        
    except Exception as e:
        print(f"❌ Error fetching logs: {str(e)}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        # Always close the client
        await client.close()


async def _fetch_with_scroll(
    client: AsyncElasticsearch,
    index: str,
    query: dict,
    max_size: int
) -> list:
    """Fetch large datasets using scroll API"""
    hits = []
    
    resp = await client.search(
        index=index,
        query=query,
        scroll='2m',
        size=1000
    )
    
    scroll_id = resp['_scroll_id']
    hits.extend([h["_source"] for h in resp["hits"]["hits"]])
    
    while len(resp['hits']['hits']) > 0 and len(hits) < max_size:
        resp = await client.scroll(scroll_id=scroll_id, scroll='2m')
        batch = [h["_source"] for h in resp["hits"]["hits"]]
        hits.extend(batch)
        print(f"📦 Fetched {len(hits)} documents...")
        
        if len(hits) >= max_size:
            hits = hits[:max_size]
            break
    
    # Clear scroll
    await client.clear_scroll(scroll_id=scroll_id)
    
    return hits


async def main():
    """Main entry point for standalone execution"""
    # Example usage with custom parameters
    df = await fetch_logs_from_es(
        index=os.getenv("ES_INDEX_NAME", "winlogbeat-*"),
        days_back=7,
        max_size=10000,
        output_path="ml/data/logs.csv",
        debug=True  # Enable debug mode
    )
    
    if not df.empty:
        print(f"\n✅ SUCCESS! Data fetched and saved.")
    else:
        print(f"\n⚠️  No data was fetched. Check the debug output above.")


if __name__ == "__main__":
    asyncio.run(main())
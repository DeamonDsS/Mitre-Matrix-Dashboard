import { X, Database } from 'lucide-react';
import { useState } from 'react';

interface ConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (config: { esUrl: string; esIndex: string }) => void;
  currentConfig: { esUrl: string; esIndex: string };
}

export default function ConfigModal({ isOpen, onClose, onSave, currentConfig }: ConfigModalProps) {
  const [esUrl, setEsUrl] = useState(currentConfig.esUrl);
  const [esIndex, setEsIndex] = useState(currentConfig.esIndex);

  if (!isOpen) return null;

  const handleSave = () => {
    onSave({ esUrl, esIndex });
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-md w-full p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-gray-700" />
            <h2 className="text-xl font-semibold text-gray-900">Elasticsearch Configuration</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Elasticsearch URL
            </label>
            <input
              type="text"
              value={esUrl}
              onChange={(e) => setEsUrl(e.target.value)}
              placeholder="http://localhost:9200"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-900 focus:border-transparent outline-none text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Index Name</label>
            <input
              type="text"
              value={esIndex}
              onChange={(e) => setEsIndex(e.target.value)}
              placeholder="mitre-attacks"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-900 focus:border-transparent outline-none text-sm"
            />
          </div>

          <div className="bg-gray-50 rounded-lg p-3 text-xs text-gray-600">
            <p className="font-medium mb-1">Note:</p>
            <p>
              Configure your Elasticsearch connection. If the connection fails, the dashboard will
              display mock data for demonstration purposes.
            </p>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors text-sm font-medium"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="flex-1 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors text-sm font-medium"
          >
            Save Configuration
          </button>
        </div>
      </div>
    </div>
  );
}

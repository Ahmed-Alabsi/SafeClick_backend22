import { useQuery } from '@tanstack/react-query';
import api from '../services/api';

interface FetchParams {
  page?: number;
  search?: string;
  [key: string]: any;
}

export function useDataList(endpoint: string, params: FetchParams = { page: 1, search: '' }) {
  return useQuery({
    queryKey: [endpoint, params],
    queryFn: async () => {
      const { data } = await api.get(endpoint, { params });
      return data;
    },
    // Keep previous data when fetching next page to avoid flickers
    placeholderData: (previousData) => previousData,
  });
}

/**
 * Elasticsearch Integration Module
 * Enables fast search and analytics on vulnerability data
 */

const elasticsearch = require('@elastic/elasticsearch');
const config = require('../config');

class ElasticsearchService {
  constructor() {
    this.client = new elasticsearch.Client({
      node: config.ELASTICSEARCH_URL || 'http://localhost:9200',
      auth: {
        username: config.ES_USER || 'elastic',
        password: config.ES_PASSWORD || 'changeme',
      },
    });
  }

  async indexVulnerability(vulnerability) {
    try {
      await this.client.index({
        index: 'vulnerabilities',
        id: vulnerability.id,
        document: {
          ...vulnerability,
          timestamp: new Date(),
          indexed_at: new Date(),
        },
      });
      return { success: true, message: 'Vulnerability indexed' };
    } catch (error) {
      console.error('Elasticsearch indexing error:', error);
      throw error;
    }
  }

  async searchVulnerabilities(query, filters = {}) {
    try {
      const response = await this.client.search({
        index: 'vulnerabilities',
        body: {
          query: {
            bool: {
              must: [
                {
                  multi_match: {
                    query: query,
                    fields: ['title', 'description', 'type'],
                  },
                },
              ],
              filter: Object.entries(filters).map(([key, value]) => ({
                term: { [key]: value },
              })),
            },
          },
          size: 20,
        },
      });

      return response.hits.hits.map((hit) => hit._source);
    } catch (error) {
      console.error('Elasticsearch search error:', error);
      throw error;
    }
  }

  async getAnalytics(field, timeRange = '30d') {
    try {
      const response = await this.client.search({
        index: 'vulnerabilities',
        body: {
          aggs: {
            distribution: {
              terms: { field: field, size: 10 },
              aggs: {
                count: { value_count: { field: field } },
              },
            },
            timeline: {
              date_histogram: {
                field: 'timestamp',
                interval: 'day',
                extended_bounds: {
                  min: `now-${timeRange}`,
                  max: 'now',
                },
              },
            },
          },
          size: 0,
        },
      });

      return response.aggregations;
    } catch (error) {
      console.error('Analytics error:', error);
      throw error;
    }
  }

  async deleteIndex(index) {
    try {
      await this.client.indices.delete({ index });
      console.log(`Index ${index} deleted`);
    } catch (error) {
      console.error('Delete index error:', error);
    }
  }
}

module.exports = new ElasticsearchService();

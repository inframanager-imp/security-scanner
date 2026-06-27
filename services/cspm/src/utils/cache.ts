import * as fs from 'fs';
import * as path from 'path';

interface CacheEntry {
  data: any;
  timestamp: number;
  ttl: number;
}

export class Cache {
  private cache: Map<string, CacheEntry> = new Map();
  private enabled: boolean;
  private ttl: number;
  private cacheDir: string;

  constructor(enabled: boolean = true, ttl: number = 3600) {
    this.enabled = enabled;
    this.ttl = ttl;
    this.cacheDir = '.cache';
    
    if (enabled && !fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  get(key: string): any | null {
    if (!this.enabled) return null;

    const entry = this.cache.get(key);
    if (!entry) return null;

    const now = Date.now();
    if (now - entry.timestamp > entry.ttl * 1000) {
      this.cache.delete(key);
      return null;
    }

    return entry.data;
  }

  set(key: string, data: any, ttl?: number): void {
    if (!this.enabled) return;

    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl: ttl || this.ttl
    });
  }

  clear(): void {
    this.cache.clear();
  }

  async loadFromFile(filename: string): Promise<void> {
    if (!this.enabled) return;

    const filepath = path.join(this.cacheDir, filename);
    if (fs.existsSync(filepath)) {
      const data = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
      Object.entries(data).forEach(([key, value]: [string, any]) => {
        this.cache.set(key, value);
      });
    }
  }

  async saveToFile(filename: string): Promise<void> {
    if (!this.enabled) return;

    const filepath = path.join(this.cacheDir, filename);
    const data = Object.fromEntries(this.cache);
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2), 'utf-8');
  }
}

export default new Cache(process.env.CACHE_ENABLED !== 'false', 
                          parseInt(process.env.CACHE_TTL || '3600', 10));

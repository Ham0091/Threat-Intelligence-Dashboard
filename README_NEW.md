# 🛡️ Advanced Threat Intelligence Dashboard

A powerful, modern web-based threat intelligence platform for OSINT reconnaissance and security analysis. Query multiple threat intelligence sources simultaneously and get comprehensive threat assessments with intelligent risk scoring.

## ✨ Features

### Core Intelligence Sources
- **VirusTotal** - Malware detection, reputation scoring, and analysis
- **AbuseIPDB** - IP abuse confidence scores and report history
- **Shodan** - Open ports, services, and network reconnaissance
- **AlienVault OTX** - Threat pulse data and reputation tracking
- **URLhaus** - Malicious URL detection and threat classification

### Dashboard Features
- 🎯 **Single & Bulk Lookups** - Scan IPs, domains, and URLs
- 📊 **Threat Scoring Algorithm** - Intelligent composite threat assessment (0-100)
- 💾 **Persistent History** - SQLite database stores all scans with full context
- 📈 **Analytics Dashboard** - Statistics and insights from your scans
- 🎨 **Modern UI** - Glassmorphism design with dark/light mode
- ⚡ **Intelligent Caching** - 1-hour cache reduces API calls
- 🔐 **API Key Management** - Secure settings panel
- 📤 **Export Data** - Save results as JSON

### Advanced Features
- **Threat Level Indicators** - Critical, High, Medium, Low classifications
- **Real-time Status Updates** - Live feedback on analysis progress
- **Responsive Design** - Works seamlessly on mobile, tablet, and desktop
- **Keyboard Shortcuts** - Defang/refang utilities for safe sharing
- **Quick Scans** - Dashboard quick-access lookup
- **Comparison Functions** - Compare multiple threat profiles
- **Rich Analytics** - Query type distribution and threat patterns

## 🚀 Quick Start

### Requirements
- Python 3.8+
- Modern web browser

### Installation

1. **Clone/Download the project**
   ```bash
   cd h:\tid
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API Keys**
   ```bash
   cp .env.example .env
   # Edit .env file with your API keys
   ```

   Get API keys from:
   - [VirusTotal](https://www.virustotal.com/gui/settings/api)
   - [AbuseIPDB](https://www.abuseipdb.com/api)
   - [Shodan](https://developer.shodan.io/)
   - [AlienVault OTX](https://otx.alienvault.com/api)
   - [URLhaus](https://urlhaus.abuse.ch/)

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open in browser**
   ```
   http://localhost:5001
   ```

## 📊 Threat Score Calculation

The dashboard uses a weighted average algorithm:
- **VirusTotal** (35%) - Malicious detections + reputation
- **AbuseIPDB** (35%) - Abuse confidence score
- **Shodan** (20%) - Open port count
- **URLhaus** (10%) - Threat classification

**Score Interpretation:**
- 🟢 **0-25**: Low Risk - Generally safe
- 🟡 **25-50**: Medium Risk - Suspicious activity
- 🟠 **50-70**: High Risk - Significant threats detected
- 🔴 **70-100**: Critical - Severe threats detected

## 🎮 Usage Guide

### Dashboard
- View overall statistics and metrics
- Access quick lookup from anywhere
- See recent scans at a glance

### Lookup & Analysis
1. Enter an IP address, domain, or URL
2. Click "Analyze" to query all sources
3. Review results and threat score
4. Use "Defang" to make data safe for sharing

### Scan History
- Browse all previous scans
- Filter by query text
- Quick re-scan of previous items

### Analytics
- View threat distribution charts
- Analyze query patterns
- Identify trends in reconnaissance

### Settings
- Add or update API keys
- Configure preferences
- Manage cached data
- Export/import configurations

## 🔌 API Endpoints

### POST `/api/lookup`
Perform a threat intelligence lookup
```json
{
  "query": "1.1.1.1"
}
```

### GET `/api/history?limit=50`
Retrieve scan history

### GET `/api/stats`
Get dashboard statistics

### POST `/api/export`
Export scan results

### POST `/api/compare`
Compare multiple queries
```json
{
  "queries": ["1.1.1.1", "8.8.8.8"]
}
```

## 📝 Database Schema

The SQLite database stores:
- Query text and hash
- Query type (IP, domain, URL)
- Composite threat score
- Full API response data
- Scan timestamp
- Cache expiration time

## 🔒 Security Notes

- API keys are stored in `.env` file (never commit to git)
- Enable HTTPS in production (use nginx/reverse proxy)
- Implement rate limiting for public deployments
- Consider authentication for sensitive environments
- Database contains scan history - encrypt in production

## 🛠️ Development

### Project Structure
```
h:\tid/
├── app.py              # Flask backend + database models
├── requirements.txt    # Python dependencies
├── .env.example        # API key template
├── .gitignore
├── README.md
├── static/
│   ├── style.css       # Modern dashboard styles
│   └── script.js       # Frontend logic
├── templates/
│   └── index.html      # Main UI
└── threat_intel.db     # SQLite database (auto-created)
```

### Tech Stack
- **Backend**: Flask 3.0, SQLAlchemy 2.0
- **Database**: SQLite
- **Frontend**: Vanilla JavaScript, modern CSS Grid
- **APIs Integrated**: VirusTotal, Shodan, AbuseIPDB, OTX, URLhaus

## 📦 Dependencies

- `flask` - Web framework
- `flask-cors` - Cross-origin support
- `requests` - HTTP library
- `python-dotenv` - Environment variables
- `sqlalchemy` - ORM database toolkit
- `whois` - Domain WHOIS lookups

## 🚨 Troubleshooting

**Issue**: "API key not configured" error
- **Solution**: Copy `.env.example` to `.env` and add your API keys

**Issue**: Database locked error
- **Solution**: Restart the application

**Issue**: API rate limiting
- **Solution**: The built-in caching (1-hour TTL) helps; upgrade API plans if needed

**Issue**: Slow response times
- **Solution**: Check your internet connection; some APIs may be slow

## 🐛 Known Limitations

- Free API tiers may have rate limits
- Some data requires paid API plans
- URLhaus and OTX are optional (gracefully degrade)
- Bulk scanning not yet optimized for 1000+ IPs

## 🔮 Future Enhancements

- [ ] GraphQL API endpoint
- [ ] Advanced threat hunting workflow
- [ ] Visual relationship graphs (NetworkX)
- [ ] CSV/PDF export functionality
- [ ] Email alerts for critical threats
- [ ] Machine learning-based threat detection
- [ ] Integration with SIEM systems
- [ ] Docker containerization
- [ ] Reverse DNS, WHOIS lookups
- [ ] GreyNoise integration
- [ ] SecurityTrails passive DNS integration

## 📄 License

MIT License - Feel free to use and modify

## 🤝 Contributing

Contributions welcome! Submit pull requests or open issues for bugs and feature requests.

## 📧 Support

For issues or questions, open a GitHub issue or contact the maintainers.

---

**Made with ❤️ for the security research community**

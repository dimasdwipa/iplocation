const express = require('express');
const cors = require('cors');
const UAParser = require('ua-parser-js');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// In-memory data store for POC
const trackingData = [];

// Helper to clean IP and handle proxy scenarios
function getClientIp(req) {
    const xForwardedFor = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    let ip = xForwardedFor || req.socket.remoteAddress;
    // Normalize localhost IP for local testing
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        ip = '127.0.0.1';
    }
    return ip;
}
// Simple cache to prevent rate limits for identical IPs
const geoCache = {};

// Robust multi-API fallback strategy for IP Geolocation
async function getGeoLocation(ip) {
    // Return cached result if available
    if (geoCache[ip]) return geoCache[ip];

    // Default normalized structure
    let result = { city: 'Unknown', region: 'Unknown', country: 'Unknown', isp: 'Unknown' };

    // Helper for AbortController timeout (e.g. 3000ms)
    const fetchWithTimeout = async (url, ms = 3000) => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), ms);
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    };

    try {
        // 1st API: ipapi.co
        const resp1 = await fetchWithTimeout(`https://ipapi.co/${ip}/json/`);
        if (resp1.ok) {
            const data1 = await resp1.json();
            // Validate completeness of data
            if (!data1.error && data1.city && data1.region) {
                console.log(`Geo Source: ipapi.co for ${ip}`);
                result = {
                    city: data1.city || 'Unknown',
                    region: data1.region || 'Unknown',
                    country: data1.country_name || 'Unknown',
                    isp: data1.org || 'Unknown'
                };
                geoCache[ip] = result;
                return result;
            }
        }
    } catch (e) { /* ignore and fallback */ }

    console.log(`Fallback to ip-api.com triggered for ${ip}`);

    try {
        // 2nd API (Fallback): ip-api.com
        const resp2 = await fetchWithTimeout(`http://ip-api.com/json/${ip}`);
        if (resp2.ok) {
            const data2 = await resp2.json();
            if (data2.status === 'success' && data2.city) {
                console.log(`Geo Source: ip-api.com for ${ip}`);
                result = {
                    city: data2.city || 'Unknown',
                    region: data2.regionName || 'Unknown',
                    country: data2.country || 'Unknown',
                    isp: data2.isp || 'Unknown'
                };
                geoCache[ip] = result;
                return result;
            }
        }
    } catch (e) { /* ignore and fallback */ }
    
    console.log(`Fallback to ipinfo.io triggered for ${ip}`);

    try {
        // 3rd API (Fallback): ipinfo.io
        const resp3 = await fetchWithTimeout(`https://ipinfo.io/${ip}/json`);
        if (resp3.ok) {
            const data3 = await resp3.json();
            if (data3.city) {
                console.log(`Geo Source: ipinfo.io for ${ip}`);
                result = {
                    city: data3.city || 'Unknown',
                    region: data3.region || 'Unknown',
                    country: data3.country || 'Unknown',
                    isp: data3.org || 'Unknown' // Often contains ASN + ISP
                };
                geoCache[ip] = result;
                return result;
            }
        }
    } catch (e) {
        console.error(`All IP Geolocation APIs failed for ${ip}`);
    }

    // Cache the unknown result to prevent spamming APIs on failure
    geoCache[ip] = result;
    return result;
}

// Root route for Railway public domain access
app.get('/', (req, res) => {
    res.redirect('/track?user_id=DEMO001');
});

// Handle the tracking link
app.get('/track', async (req, res) => {
    const userId = req.query.user_id || 'anonymous';
    const ip = getClientIp(req);

    // Parse User-Agent
    const uaString = req.headers['user-agent'] || '';
    const parser = new UAParser(uaString);
    const uaResult = parser.getResult();

    const deviceBrand = uaResult.device.vendor || 'Unknown';
    const osName = uaResult.os.name || 'Unknown';
    const deviceStr = `${deviceBrand} / ${osName}`;
    const browserStr = uaResult.browser.name || 'Unknown';

    // Get normalized IP Geolocation with multi-API fallback
    const { city, region, country, isp } = await getGeoLocation(ip);

    const sessionId = Date.now().toString() + Math.random().toString(36).substring(2, 8);
    
    // Store in exact JSON structure requested
    const sessionData = {
        sessionId, // Kept for internal matching but omitted in output
        user_id: userId,
        ip: ip,
        city: city,
        region: region,
        country: country,
        isp: isp,
        device: deviceStr,
        browser: browserStr,
        screen: "Pending...",
        timezone: "Pending...",
        gps: "Pending..."
    };

    trackingData.push(sessionData);
    console.log(`[New Session Captured] User: ${userId}, Session: ${sessionId}`);

    // Read the tracking page template and inject sessionId so frontend can update it
    let htmlTemplate = fs.readFileSync(path.join(__dirname, 'public', 'track.html'), 'utf-8');
    htmlTemplate = htmlTemplate.replace('{{SESSION_ID}}', sessionId);
    htmlTemplate = htmlTemplate.replace('{{TARGET_URL}}', '/success.html');

    res.send(htmlTemplate);
});

// Endpoint to receive precise geolocation and enriched client data from frontend
app.post('/api/location', (req, res) => {
    const { sessionId, latitude, longitude, error, screen, timezone } = req.body;
    
    const session = trackingData.find(s => s.sessionId === sessionId);
    if (session) {
        if (screen) session.screen = screen;
        if (timezone) session.timezone = timezone;

        if (latitude && longitude) {
            session.gps = `${latitude}, ${longitude}`;
            console.log(`[Location Updated] Session: ${sessionId}, Method: GPS`);
        } else if (error) {
            session.gps = "denied or unavailable";
            console.log(`[Location Denied/Failed] Session: ${sessionId}, Error: ${error}`);
        }
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, message: 'Session not found' });
    }
});

// Admin endpoint to view structured data
app.get('/admin/data', (req, res) => {
    // Remove internal sessionId to match exactly the required JSON format
    const cleanData = trackingData.map(({ sessionId, ...rest }) => rest);
    res.json(cleanData);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Tracking server running on port ${PORT}`);
    console.log(`App accessible via Railway domain`);
    console.log(`Test link: http://localhost:${PORT}/track?user_id=EMP001`);
    console.log(`Admin Data link: http://localhost:${PORT}/admin/data`);
});

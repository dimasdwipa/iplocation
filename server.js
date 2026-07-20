const express = require('express');
const cors = require('cors');
const UAParser = require('ua-parser-js');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Add UA-CH and Permissions-Policy headers for high-entropy client hints
app.use((req, res, next) => {
    res.setHeader('Accept-CH', 'Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Form-Factors, Sec-CH-UA-Mobile');
    res.setHeader('Permissions-Policy', 'ch-ua-form-factors=*, ch-ua-full-version-list=*, ch-ua-model=*, ch-ua-platform=*, ch-ua-platform-version=*, ch-ua-arch=*, ch-ua-bitness=*');
    next();
});

app.use(express.static('public'));

// In-memory data store for POC
const trackingData = [];

// Helper to clean IP
function getClientIp(req) {
    const xForwardedFor = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    let ip = xForwardedFor || req.socket.remoteAddress;
    if (ip === '::1' || ip === '::ffff:127.0.0.1') ip = '127.0.0.1';
    return ip;
}

// Simple cache to prevent rate limits for identical IPs
const geoCache = {};

// Robust multi-API fallback strategy for IP Geolocation
async function getGeoLocation(ip) {
    if (geoCache[ip]) return geoCache[ip];
    let result = { city: 'Unknown', region: 'Unknown', country: 'Unknown', isp: 'Unknown' };

    const fetchWithTimeout = async (url, ms = 3000) => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), ms);
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    };

    try {
        const resp1 = await fetchWithTimeout(`https://ipapi.co/${ip}/json/`);
        if (resp1.ok) {
            const data1 = await resp1.json();
            if (!data1.error && data1.city && data1.region) {
                result = { city: data1.city || 'Unknown', region: data1.region || 'Unknown', country: data1.country_name || 'Unknown', isp: data1.org || 'Unknown' };
                geoCache[ip] = result; return result;
            }
        }
    } catch (e) { }

    try {
        const resp2 = await fetchWithTimeout(`http://ip-api.com/json/${ip}`);
        if (resp2.ok) {
            const data2 = await resp2.json();
            if (data2.status === 'success' && data2.city) {
                result = { city: data2.city || 'Unknown', region: data2.regionName || 'Unknown', country: data2.country || 'Unknown', isp: data2.isp || 'Unknown' };
                geoCache[ip] = result; return result;
            }
        }
    } catch (e) { }
    
    try {
        const resp3 = await fetchWithTimeout(`https://ipinfo.io/${ip}/json`);
        if (resp3.ok) {
            const data3 = await resp3.json();
            if (data3.city) {
                result = { city: data3.city || 'Unknown', region: data3.region || 'Unknown', country: data3.country || 'Unknown', isp: data3.org || 'Unknown' };
                geoCache[ip] = result; return result;
            }
        }
    } catch (e) { }

    geoCache[ip] = result;
    return result;
}

// Reverse Geocoding using Nominatim API
async function reverseGeocode(lat, lon) {
    let result = { gps_address: 'Unknown', gps_city: 'Unknown', gps_region: 'Unknown', gps_country: 'Unknown' };
    try {
        const url = `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json`;
        const headers = { 'User-Agent': 'iplocation-poc/1.0' };
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const response = await fetch(url, { headers, signal: controller.signal });
        clearTimeout(timeoutId);

        if (response.ok) {
            const data = await response.json();
            if (data && data.address) {
                const addr = data.address;
                result.gps_address = data.display_name || 'Unknown';
                result.gps_city = addr.city || addr.town || addr.village || addr.county || 'Unknown';
                result.gps_region = addr.state || addr.region || 'Unknown';
                result.gps_country = addr.country || 'Unknown';
            }
        }
    } catch (error) {
        console.error('Reverse Geocoding error:', error.message);
    }
    return result;
}

// Helper: Resolve Marketing Name
function resolveMarketingName(model) {
    if (!model || model === 'Unknown') return 'Unknown';
    // Explicit and maintainable mapping dictionary
    const mappings = {
        'SM-S928B': 'Samsung Galaxy S24 Ultra',
        'SM-S918B': 'Samsung Galaxy S23 Ultra',
        'SM-G998B': 'Samsung Galaxy S21 Ultra',
        'iPhone15,2': 'Apple iPhone 14 Pro',
        'iPhone15,3': 'Apple iPhone 14 Pro Max',
        'iPhone16,1': 'Apple iPhone 15 Pro',
        'iPhone16,2': 'Apple iPhone 15 Pro Max',
        'Pixel 8 Pro': 'Google Pixel 8 Pro'
    };
    return mappings[model] || 'Unknown';
}

// Helper: Generate Device Profile ID (SHA-256)
function generateDeviceProfileId(profile) {
    const raw = [
        profile.device_type,
        profile.brand,
        profile.model,
        profile.os,
        profile.os_version,
        profile.browser,
        profile.browser_version,
        profile.platform,
        Array.isArray(profile.form_factors) ? profile.form_factors.join(',') : '',
        profile.screen,
        profile.timezone
    ].join('|');
    return crypto.createHash('sha256').update(raw).digest('hex');
}

// Root route for Railway public domain access
app.get('/', (req, res) => res.redirect('/track?user_id=DEMO001'));

// Handle the tracking link
app.get('/track', async (req, res) => {
    const userId = req.query.user_id || 'anonymous';
    const ip = getClientIp(req);
    const { city, region, country, isp } = await getGeoLocation(ip);
    const sessionId = Date.now().toString() + Math.random().toString(36).substring(2, 8);
    
    // Initial session setup (Device Profile will be populated via POST from client-side UA-CH enrichment)
    const sessionData = {
        sessionId,
        user_id: userId,
        ip: ip,
        ip_city: city,
        ip_region: region,
        ip_country: country,
        isp: isp,
        gps: "Pending...",
        gps_address: "Pending...",
        gps_city: "Pending...",
        gps_region: "Pending...",
        gps_country: "Pending...",
        final_city: city,
        final_region: region,
        final_country: country,
        location_source: "IP",
        device_profile: null // Will be enriched
    };

    trackingData.push(sessionData);
    console.log(`[New Session Captured] User: ${userId}, Session: ${sessionId}`);

    let htmlTemplate = fs.readFileSync(path.join(__dirname, 'public', 'track.html'), 'utf-8');
    htmlTemplate = htmlTemplate.replace('{{SESSION_ID}}', sessionId);
    htmlTemplate = htmlTemplate.replace('{{TARGET_URL}}', '/success.html');

    res.send(htmlTemplate);
});

// Endpoint to receive geolocation AND rich device profile
app.post('/api/location', async (req, res) => {
    console.log("API LOCATION HIT:", req.body);
    const { sessionId, latitude, longitude, error, deviceData } = req.body;
    
    const session = trackingData.find(s => s.sessionId === sessionId);
    if (!session) {
        console.log("Session NOT FOUND:", sessionId);
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    console.log("Session found:", sessionId);

    // Process Device Profile Enrichment
    if (deviceData) {
        // Fallback to UA string if UA-CH is completely absent
        const parser = new UAParser(deviceData.userAgent || '');
        const uaResult = parser.getResult();

        let brand = 'Unknown', model = 'Unknown', os = 'Unknown', os_version = 'Unknown';
        let browser = 'Unknown', browser_version = 'Unknown', platform = 'Unknown';
        let architecture = 'Unknown', bitness = 'Unknown', platform_version = 'Unknown';
        let form_factors = [];
        let device_type = 'desktop';
        let ua_source = 'UA-PARSER';
        let confidence = 'LOW';

        // Check if UA-CH provided data
        if (deviceData.uach && Object.keys(deviceData.uach).length > 0) {
            console.log(`[Device Profiling] UA-CH supported for session ${sessionId}`);
            ua_source = 'UA-CH';
            const ch = deviceData.uach;
            
            architecture = ch.architecture || 'Unknown';
            bitness = ch.bitness || 'Unknown';
            model = ch.model || 'Unknown';
            platform = ch.platform || 'Unknown';
            platform_version = ch.platformVersion || 'Unknown';
            form_factors = ch.formFactors || [];
            
            // Extract best brand from brands array
            if (ch.brands && ch.brands.length > 0) {
                const validBrand = ch.brands.find(b => !b.brand.includes('Not') && !b.brand.includes('Brand'));
                if (validBrand) {
                    browser = validBrand.brand;
                    browser_version = validBrand.version;
                }
            }

            if (ch.mobile) device_type = 'mobile';
            else if (form_factors.includes('Tablet')) device_type = 'tablet';
            
            // Assign confidence
            if (model !== 'Unknown' && model !== '') {
                confidence = 'HIGH';
                console.log(`[Device Profiling] UA-CH exact model received: ${model}`);
            } else {
                confidence = 'MEDIUM';
            }
        } else {
            console.log(`[Device Profiling] Fallback to UA parser for session ${sessionId}`);
            brand = uaResult.device.vendor || 'Unknown';
            model = uaResult.device.model || 'Unknown';
            os = uaResult.os.name || 'Unknown';
            os_version = uaResult.os.version || 'Unknown';
            browser = uaResult.browser.name || 'Unknown';
            browser_version = uaResult.browser.version || 'Unknown';
            device_type = uaResult.device.type || 'desktop';
            
            if (brand !== 'Unknown' && os !== 'Unknown' && browser !== 'Unknown') confidence = 'MEDIUM';
        }

        // Fill gaps if UA-CH was partial
        if (os === 'Unknown') os = platform !== 'Unknown' ? platform : (uaResult.os.name || 'Unknown');
        if (brand === 'Unknown') brand = uaResult.device.vendor || 'Unknown';
        if (browser === 'Unknown') browser = uaResult.browser.name || 'Unknown';
        if (browser_version === 'Unknown') browser_version = uaResult.browser.version || 'Unknown';

        console.log(`[Device Profiling] Device model confidence: ${confidence}`);

        const profile = {
            device_type,
            brand,
            model,
            marketing_name: resolveMarketingName(model),
            os,
            os_version,
            browser,
            browser_version,
            platform,
            platform_version,
            architecture,
            bitness,
            form_factors,
            screen: deviceData.screen || 'Unknown',
            device_pixel_ratio: deviceData.devicePixelRatio || 1,
            language: deviceData.language || 'Unknown',
            timezone: deviceData.timezone || 'Unknown',
            touch_points: deviceData.maxTouchPoints || 0,
            hardware_concurrency: deviceData.hardwareConcurrency || 'Unknown',
            device_memory_gb: deviceData.deviceMemory || 'Unknown',
            network_type: deviceData.networkType || 'Unknown',
            ua_source,
            device_model_confidence: confidence
        };

        profile.device_profile_id = generateDeviceProfileId(profile);
        session.device_profile = profile;
    }

    // Process GPS
    if (latitude && longitude) {
        console.log("GPS received:", latitude, longitude);
        session.gps = `${latitude}, ${longitude}`;
        console.log(`[Location Updated] Session: ${sessionId}, Method: GPS`);
        
        const geo = await reverseGeocode(latitude, longitude);
        session.gps_address = geo.gps_address;
        session.gps_city = geo.gps_city;
        session.gps_region = geo.gps_region;
        session.gps_country = geo.gps_country;
        
        session.final_city = geo.gps_city !== 'Unknown' ? geo.gps_city : session.ip_city;
        session.final_region = geo.gps_region !== 'Unknown' ? geo.gps_region : session.ip_region;
        session.final_country = geo.gps_country !== 'Unknown' ? geo.gps_country : session.ip_country;
        session.location_source = "GPS";
    } else if (error) {
        session.gps = "denied or unavailable";
        session.location_source = "IP";
        console.log(`[Location Denied/Failed] Session: ${sessionId}, Error: ${error}`);
    }

    res.json({ success: true });
});

// Admin endpoint to view structured data
app.get('/admin/data', (req, res) => {
    const cleanData = trackingData.map(({ sessionId, ...rest }) => rest);
    res.json(cleanData);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Tracking server running on port ${PORT}`);
    console.log(`App accessible via Railway domain`);
    console.log(`Test link: http://localhost:${PORT}/track?user_id=EMP001`);
    console.log(`Admin Data link: http://localhost:${PORT}/admin/data`);
});

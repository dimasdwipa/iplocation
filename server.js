const express = require('express');
const cors = require('cors');
const DeviceDetector = require('device-detector-js');
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
        'SM-S938B': 'Samsung Galaxy S25 Ultra',
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
    
    // Initial session setup with empty device_profile schema to prevent null
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
        status: "pending",
        clientSessionKey: null,
        device_profile: {
            device_type: "Unknown",
            brand: "Unknown",
            model: "Unknown",
            marketing_name: "Unknown",
            os: "Unknown",
            os_version: "Unknown",
            browser: "Unknown",
            browser_version: "Unknown",
            platform: "Unknown",
            platform_version: "Unknown",
            architecture: "Unknown",
            bitness: "Unknown",
            form_factors: [],
            screen: "Unknown",
            device_pixel_ratio: 1,
            language: "Unknown",
            timezone: "Unknown",
            touch_points: 0,
            hardware_concurrency: "Unknown",
            device_memory_gb: "Unknown",
            network_type: "Unknown",
            ua_source: "NONE",
            device_model_confidence: "LOW",
            device_profile_id: "Unknown"
        }
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
    const { sessionId, clientSessionKey, status, latitude, longitude, error, deviceData } = req.body;
    
    let session = null;
    
    // Duplicate Prevention Logic
    if (clientSessionKey) {
        // Try to find an existing session for this exact client browser tab
        const existingSession = trackingData.find(s => s.clientSessionKey === clientSessionKey);
        
        if (existingSession) {
            session = existingSession;
            console.log(`[Session Reused] ClientKey: ${clientSessionKey}`);
            
            // Clean up the dummy pending session created by this new GET /track load
            if (sessionId && sessionId !== session.sessionId) {
                const idx = trackingData.findIndex(s => s.sessionId === sessionId && s.status === 'pending');
                if (idx !== -1) {
                    trackingData.splice(idx, 1);
                    console.log(`[Duplicate Cleaned] Removed redundant pending session: ${sessionId}`);
                }
            }
        }
    }

    // Fallback if no existing session was found (first time POST)
    if (!session) {
        session = trackingData.find(s => s.sessionId === sessionId);
    }
    
    if (!session) {
        console.log("Session NOT FOUND:", sessionId);
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    // Assign client key on first connect
    if (clientSessionKey && !session.clientSessionKey) {
        session.clientSessionKey = clientSessionKey;
    }
    
    // Update lifecycle status
    if (status) {
        session.status = status;
        console.log(`[Session Status] ${session.sessionId} -> ${status}`);
    } else if (session.status === 'pending') {
        session.status = 'active';
    }

    // Block 1: Device Profile Enrichment (Wrapped in try/catch to prevent crashes)
    try {
        if (deviceData) {
            const rawUA = deviceData.userAgent || '';
            
            // Priority C: device-detector-js (Best for Android generic mapping)
            const detector = new DeviceDetector();
            const ddResult = detector.parse(rawUA);
            
            // Priority B: ua-parser-js (Best for standard OS/Browser names and Safari)
            const parser = new UAParser(rawUA);
            const uapResult = parser.getResult();

            let brand = 'Unknown', model = 'Unknown', os = 'Unknown', os_version = 'Unknown';
            let browser = 'Unknown', browser_version = 'Unknown', platform = 'Unknown';
            let architecture = 'Unknown', bitness = 'Unknown', platform_version = 'Unknown';
            let form_factors = [];
            let device_type = 'desktop';
            let ua_source = 'UA-PARSER';
            let confidence = 'LOW';

            // 1. Fill base layers with Priority C (device-detector-js)
            if (ddResult.device) {
                brand = ddResult.device.brand || 'Unknown';
                model = ddResult.device.model || 'Unknown';
                device_type = ddResult.device.type || 'desktop';
            }
            if (ddResult.os) {
                os = ddResult.os.name || 'Unknown';
                os_version = ddResult.os.version || 'Unknown';
            }
            if (ddResult.client) {
                browser = ddResult.client.name || 'Unknown';
                browser_version = ddResult.client.version || 'Unknown';
            }

            // 2. Enhance with Priority B (ua-parser-js)
            if (brand === 'Unknown') brand = uapResult.device.vendor || 'Unknown';
            if (model === 'Unknown') model = uapResult.device.model || 'Unknown';
            if (os === 'Unknown') os = uapResult.os.name || 'Unknown';
            if (os_version === 'Unknown') os_version = uapResult.os.version || 'Unknown';
            if (browser === 'Unknown') browser = uapResult.browser.name || 'Unknown';
            if (browser_version === 'Unknown') browser_version = uapResult.browser.version || 'Unknown';
            if (device_type === 'desktop') device_type = uapResult.device.type || 'desktop'; // If still generic desktop, allow UAParser to override

            // 3. Absolute Override with Priority A (UA-CH) if available
            if (deviceData.uach && Object.keys(deviceData.uach).length > 0) {
                console.log(`[Device Profiling] UA-CH supported for session ${sessionId}`);
                ua_source = 'UA-CH';
                const ch = deviceData.uach;
                
                architecture = ch.architecture || 'Unknown';
                bitness = ch.bitness || 'Unknown';
                if (ch.model) model = ch.model;
                if (ch.platform) platform = ch.platform;
                platform_version = ch.platformVersion || 'Unknown';
                if (ch.formFactors) form_factors = ch.formFactors;
                
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
                
                if (model !== 'Unknown' && model !== '') {
                    confidence = 'HIGH';
                } else {
                    confidence = 'MEDIUM';
                }
            } else {
                console.log(`[Device Profiling] Fallback to legacy parsing for session ${sessionId}`);
                if (brand !== 'Unknown' && os !== 'Unknown' && browser !== 'Unknown') confidence = 'MEDIUM';
            }

            // Final gap fills
            if (os === 'Unknown') os = platform !== 'Unknown' ? platform : 'Unknown';
            
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
    } catch (profileError) {
        console.error(`[Error] Device profile parsing failed for session ${sessionId}:`, profileError);
        // We let the pre-populated "Unknown" defaults remain in the session object
    }

    // Block 2: Process GPS (Wrapped in try/catch)
    try {
        if (latitude && longitude) {
            console.log("GPS received:", latitude, longitude);
            
            // Initialize location history if it doesn't exist
            if (!session.location_history) {
                session.location_history = [];
            }
            
            // Push the new coordinate to history
            const timestamp = req.body.timestamp || Date.now();
            session.location_history.push({
                latitude,
                longitude,
                timestamp: new Date(timestamp).toISOString()
            });

            // Keep the flat fields updated with the LATEST known position
            session.gps = `${latitude}, ${longitude}`;
            session.location_source = "GPS";
            console.log(`[Location Updated] Session: ${sessionId}, Method: GPS, Total Points: ${session.location_history.length}`);
            
            // We only need to reverse geocode if this is the FIRST time we got GPS (to save API calls)
            // or if they have moved significantly (for simplicity in this POC, we check if it's "Pending...")
            if (session.gps_address === "Pending...") {
                const geo = await reverseGeocode(latitude, longitude);
                session.gps_address = geo.gps_address;
                session.gps_city = geo.gps_city;
                session.gps_region = geo.gps_region;
                session.gps_country = geo.gps_country;
                
                session.final_city = geo.gps_city !== 'Unknown' ? geo.gps_city : session.ip_city;
                session.final_region = geo.gps_region !== 'Unknown' ? geo.gps_region : session.ip_region;
                session.final_country = geo.gps_country !== 'Unknown' ? geo.gps_country : session.ip_country;
            }
        } else if (error && !session.location_history) {
            // Only set to denied if they NEVER provided location history
            session.gps = "denied or unavailable";
            session.gps_address = "denied or unavailable";
            session.location_source = "IP";
            console.log(`[Location Denied/Failed] Session: ${sessionId}, Error: ${error}`);
        } else if (!session.location_history) {
            // Failsafe in case nothing was passed and we have no history
            session.gps = "denied or unavailable";
            session.gps_address = "denied or unavailable";
            session.location_source = "IP";
            console.log(`[Location] Neither GPS nor Error received for session: ${sessionId}`);
        }
    } catch (gpsError) {
        console.error(`[Error] GPS processing failed for session ${sessionId}:`, gpsError);
        session.gps = "error";
        session.gps_address = "error";
    }

    res.json({ success: true });
});

// --- Helper functions for Admin Data Merging ---

function scoreDeviceProfileRichness(profile) {
    if (!profile) return -1;
    let score = 0;
    if (profile.ua_source !== 'NONE') score += 10;
    if (profile.ua_source === 'UA-CH') score += 20; // Highest quality
    if (profile.device_model_confidence === 'HIGH') score += 15;
    
    const fields = Object.values(profile);
    for (const val of fields) {
        if (val !== 'Unknown' && val !== '' && val !== null && val !== 0 && (!Array.isArray(val) || val.length > 0)) {
            score += 1;
        }
    }
    return score;
}

function chooseLatestMeaningfulValue(a, b) {
    const isMeaningless = (val) => !val || val === 'Unknown' || val === 'Pending...' || val === 'denied or unavailable' || val === 'error';
    if (isMeaningless(a)) return b;
    if (isMeaningless(b)) return a;
    return b; // Assumes 'b' is the newer record in chronological processing array
}

function mergeLocationHistory(historyArrays) {
    const combined = [];
    for (const arr of historyArrays) {
        if (Array.isArray(arr)) combined.push(...arr);
    }
    
    // Deduplicate by timestamp and lat/lon
    const unique = [];
    const seen = new Set();
    for (const pt of combined) {
        const key = `${pt.timestamp}_${pt.latitude}_${pt.longitude}`;
        if (!seen.has(key)) {
            seen.add(key);
            unique.push(pt);
        }
    }
    
    return unique.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

function chooseBestStatus(statuses) {
    if (statuses.includes('active')) return 'active';
    if (statuses.includes('hidden')) return 'hidden';
    if (statuses.includes('completed')) return 'completed';
    if (statuses.includes('pending')) return 'pending';
    return 'abandoned';
}

// Admin endpoint to view structured data safely merged
app.get('/admin/data', (req, res) => {
    const showAll = req.query.all === 'true';
    
    // Filter out abandoned/pending sessions by default
    const activeData = trackingData.filter(s => showAll || (s.status !== 'pending' && s.status !== 'abandoned'));
    
    // Group by device_profile_id + user_id
    const groups = {};
    const unmergable = [];
    
    for (const session of activeData) {
        const dpId = session.device_profile?.device_profile_id;
        
        // If missing or Unknown, do not merge blindly
        if (!dpId || dpId === 'Unknown') {
            unmergable.push({ ...session });
            continue;
        }
        
        // Group key uses both user_id and device_profile_id to prevent cross-user merging
        const groupKey = `${session.user_id}_${dpId}`;
        if (!groups[groupKey]) {
            groups[groupKey] = [];
        }
        groups[groupKey].push(session);
    }
    
    const mergedData = [];
    
    for (const groupKey in groups) {
        const cluster = groups[groupKey];
        if (cluster.length === 1) {
            const single = { ...cluster[0] };
            single.merged_session_count = 1;
            mergedData.push(single);
            continue;
        }
        
        const merged = { ...cluster[0] }; 
        const historyArrays = [];
        const statuses = [];
        let bestProfileScore = -1;
        const mergedFromIds = [];
        
        for (const s of cluster) {
            mergedFromIds.push(s.sessionId);
            statuses.push(s.status);
            if (s.location_history) historyArrays.push(s.location_history);
            
            merged.ip = chooseLatestMeaningfulValue(merged.ip, s.ip);
            merged.ip_city = chooseLatestMeaningfulValue(merged.ip_city, s.ip_city);
            merged.ip_region = chooseLatestMeaningfulValue(merged.ip_region, s.ip_region);
            merged.ip_country = chooseLatestMeaningfulValue(merged.ip_country, s.ip_country);
            merged.isp = chooseLatestMeaningfulValue(merged.isp, s.isp);
            
            merged.gps = chooseLatestMeaningfulValue(merged.gps, s.gps);
            merged.gps_address = chooseLatestMeaningfulValue(merged.gps_address, s.gps_address);
            merged.gps_city = chooseLatestMeaningfulValue(merged.gps_city, s.gps_city);
            merged.gps_region = chooseLatestMeaningfulValue(merged.gps_region, s.gps_region);
            merged.gps_country = chooseLatestMeaningfulValue(merged.gps_country, s.gps_country);
            
            merged.final_city = chooseLatestMeaningfulValue(merged.final_city, s.final_city);
            merged.final_region = chooseLatestMeaningfulValue(merged.final_region, s.final_region);
            merged.final_country = chooseLatestMeaningfulValue(merged.final_country, s.final_country);
            merged.location_source = chooseLatestMeaningfulValue(merged.location_source, s.location_source);
            
            const pScore = scoreDeviceProfileRichness(s.device_profile);
            if (pScore > bestProfileScore) {
                bestProfileScore = pScore;
                merged.device_profile = s.device_profile;
            }
        }
        
        merged.location_history = mergeLocationHistory(historyArrays);
        merged.status = chooseBestStatus(statuses);
        merged.merged_session_count = cluster.length;
        merged.merged_from_session_ids = mergedFromIds; // Debugging tracking
        
        mergedData.push(merged);
    }
    
    const finalData = [...mergedData, ...unmergable];
    
    // Strip raw internal identifiers for clean output
    const cleanData = finalData.map(({ sessionId, clientSessionKey, ...rest }) => rest);
    
    res.json(cleanData);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Tracking server running on port ${PORT}`);
    console.log(`App accessible via Railway domain`);
    console.log(`Test link: http://localhost:${PORT}/track?user_id=EMP001`);
    console.log(`Admin Data link: http://localhost:${PORT}/admin/data`);
});

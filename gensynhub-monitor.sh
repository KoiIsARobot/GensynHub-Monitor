#!/bin/bash

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

VERSION="1.0.0"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ "$SCRIPT_DIR" == *"/rl-swarm"* ]]; then
    SWARM_DIR="$SCRIPT_DIR"
elif [ -d "$SCRIPT_DIR/rl-swarm" ]; then
    SWARM_DIR="$SCRIPT_DIR/rl-swarm"
elif [ -d "./rl-swarm" ]; then
    SWARM_DIR="$(pwd)/rl-swarm"
else
    SWARM_DIR="$SCRIPT_DIR"
fi
MONITOR_DIR="$SWARM_DIR/gensyn-hub-monitor"
MONITOR_SCRIPT="$MONITOR_DIR/gensyn-monitor.js"
GENSYN_HUB_URL="${GENSYN_HUB_URL:-https://www.gensyn.info}"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log() {
    echo -e "${CYAN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# ============================================================================
# PROCESS CLEANUP FUNCTIONS
# ============================================================================

cleanup_existing_monitors() {
    log "Checking for existing monitor processes..."

    # Find all gensyn-monitor related processes
    local found_processes=false

    # Check for node processes running gensyn-monitor.js
    if pgrep -f "node.*gensyn-monitor.js" > /dev/null 2>&1; then
        warning "Found existing monitor processes running"
        found_processes=true
        pkill -f "node.*gensyn-monitor.js" || true
    fi

    # Check for old shell script monitors
    if pgrep -f "gensynhub-monitor.sh" > /dev/null 2>&1; then
        warning "Found old shell script monitors running"
        found_processes=true
        pkill -f "gensynhub-monitor.sh" || true
    fi

    # Check for any monitor.js variations
    if pgrep -f "monitor.js.*gensyn" > /dev/null 2>&1; then
        warning "Found other monitor variations running"
        found_processes=true
        pkill -f "monitor.js.*gensyn" || true
    fi

    # Also check for daemon wrapper processes
    if [ -f "$MONITOR_DIR/monitor.pid" ]; then
        local old_pid=$(cat "$MONITOR_DIR/monitor.pid" 2>/dev/null || echo "")
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            warning "Found daemon process with PID $old_pid"
            found_processes=true
            kill -TERM "$old_pid" 2>/dev/null || true
            pkill -TERM -P "$old_pid" 2>/dev/null || true
        fi
        rm -f "$MONITOR_DIR/monitor.pid"
    fi

    if [ "$found_processes" = true ]; then
        success "Cleaned up existing monitor processes"
        log "Waiting for processes to terminate..."
        sleep 3

        # Double-check they're gone
        if pgrep -f "gensyn-monitor.js" > /dev/null 2>&1; then
            warning "Some processes still running, forcing termination..."
            pkill -9 -f "gensyn-monitor.js" 2>/dev/null || true
            sleep 1
        fi
    else
        log "No existing monitor processes found"
    fi
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

check_nodejs() {
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node -v)
        log "Node.js is installed: $NODE_VERSION"
        return 0
    else
        log "Node.js is not installed"
        return 1
    fi
}

install_nodejs() {
    log "Installing Node.js..."

    if command -v apt-get &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif command -v yum &> /dev/null; then
        curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
        sudo yum install -y nodejs
    elif command -v brew &> /dev/null; then
        brew install node
    else
        error "Cannot auto-install Node.js. Please install manually from https://nodejs.org"
        exit 1
    fi

    if command -v node &> /dev/null; then
        success "Node.js installed successfully"
    else
        error "Failed to install Node.js"
        exit 1
    fi
}

setup_directories() {
    log "Setting up monitor in: $MONITOR_DIR"
    mkdir -p "$MONITOR_DIR"
    mkdir -p "$SWARM_DIR/logs"
    success "Monitor directory created"
}

# ============================================================================
# MONITOR SCRIPT v2.2 (with all fixes incorporated)
# ============================================================================

create_monitor_script() {
    log "Creating monitor script v${VERSION}..."

    cat > "$MONITOR_SCRIPT" << 'MONITOR_EOF'
#!/usr/bin/env node

const os = require('os');
const fs = require('fs');
const path = require('path');
const { exec, execSync } = require('child_process');
const https = require('https');
const readline = require('readline');

const SCRIPT_PATH = process.argv[1];
const MONITOR_DIR = path.dirname(SCRIPT_PATH);
const SWARM_DIR = path.dirname(MONITOR_DIR);

const CONFIG = {
  dashboardUrl: process.env.GENSYN_HUB_URL || 'https://www.gensyn.info',
  updateInterval: 5000,
  swarmDir: SWARM_DIR,
  swarmLogFile: path.join(SWARM_DIR, 'logs/swarm.log'),
  credentialsFile: path.join(MONITOR_DIR, 'credentials.json'),
  cacheFile: path.join(MONITOR_DIR, 'cache.json'),
  lockFile: path.join(MONITOR_DIR, 'monitor.lock')
};

let authToken = null;
let nodeId = null;
let isMonitoring = false;
let peerInfo = null;
let lastLogPosition = 0;
let logWatcher = null;
let updatesSent = 0;
let locationFetchInterval = null;

// Uptime tracking
let monitorStartTime = Date.now();
let swarmActiveTime = 0;
let lastSwarmCheck = Date.now();
let isSwarmActive = false;

// CPU tracking for usage calculation
let previousCpuInfo = null;

// Error patterns to detect
const ERROR_PATTERNS = [
  /UnboundLocalError/i,
  /Terminated/i,
  />> Shutting down trainer\.\.\./,
  /An error was detected/i,
  /KeyboardInterrupt/i,
  /Exception:/i,
  /Error:/i,
  /Failed to/i,
  /CUDA out of memory/i,
  /Connection refused/i,
  /Traceback \(most recent call last\)/i,
  /AssertionError/i,
  /RuntimeError/i,
  /ValueError/i,
  /TypeError/i
];

// Activity patterns
const ACTIVITY_PATTERNS = [
  /Starting training/i,
  /Joining round/i,
  /Training round/i,
  /Training step/i,
  /Downloading model/i,
  /Uploading model/i,
  /✅\s*Connected to Gensyn Testnet/i,
  /Connected to Gensyn Testnet/i,
  /Peer ID\s*\[[^\]]+\]\s*is already registered/i,
  /🐱\s*Hello\s*🐈/i
];

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m'
};

function log(message, color = '') {
  const timestamp = new Date().toISOString();
  console.log(`${color}[${timestamp}] ${message}${colors.reset}`);
}

function error(message) {
  log(`ERROR: ${message}`, colors.red);
}

function success(message) {
  log(message, colors.green);
}

function info(message) {
  log(message, colors.cyan);
}

function warning(message) {
  log(`WARNING: ${message}`, colors.yellow);
}

function debug(message) {
  if (process.env.DEBUG === 'true') {
    log(`DEBUG: ${message}`, colors.yellow);
  }
}

// Cache management
function loadCache() {
  try {
    if (fs.existsSync(CONFIG.cacheFile)) {
      return JSON.parse(fs.readFileSync(CONFIG.cacheFile, 'utf8'));
    }
  } catch (e) {
    warning('Failed to load cache, starting fresh');
  }
  return {
    locationLastFetched: 0,
    location: null,
    nodeId: null,
    peerInfo: null
  };
}

function saveCache(cache) {
  try {
    fs.writeFileSync(CONFIG.cacheFile, JSON.stringify(cache, null, 2));
  } catch (e) {
    error('Failed to save cache: ' + e.message);
  }
}

// Handle node not found errors and trigger re-registration
async function handleNodeNotFound() {
  warning('Node not found on dashboard. Clearing cached node ID and re-registering...');

  // Clear the cached node ID
  nodeId = null;
  const cache = loadCache();
  cache.nodeId = null;
  saveCache(cache);

  // Attempt to re-register the node
  const registrationSuccess = await registerOrUpdateNode();

  if (registrationSuccess) {
    success('Node re-registered successfully');
    return true;
  } else {
    error('Failed to re-register node');
    return false;
  }
}

// Get IP address and location with caching
async function getLocationInfo(forceRefresh = false) {
  const cache = loadCache();
  const now = Date.now();
  const THIRTY_MINUTES = 30 * 60 * 1000;

  // Use cached location if available and not expired
  if (!forceRefresh && cache.location && (now - cache.locationLastFetched) < THIRTY_MINUTES) {
    debug('Using cached location data');
    return cache.location;
  }

  return new Promise((resolve) => {
    exec('curl -s ifconfig.me || curl -s icanhazip.com || curl -s ipinfo.io/ip', { timeout: 10000 }, (err, stdout) => {
      if (!err && stdout) {
        const ip = stdout.trim();

        // Use ipapi.co which supports both IPv4 and IPv6
        exec(`curl -s "https://ipapi.co/${ip}/json/" -H "User-Agent: Mozilla/5.0"`, { timeout: 10000 }, (err2, stdout2) => {
          if (!err2 && stdout2) {
            try {
              const locationData = JSON.parse(stdout2);
              if (!locationData.error && locationData.country_name) {
                const location = {
                  ip: ip,
                  country: locationData.country_name,
                  countryCode: locationData.country_code,
                  region: locationData.region,
                  city: locationData.city,
                  lat: locationData.latitude,
                  lon: locationData.longitude
                };

                // Update cache
                cache.location = location;
                cache.locationLastFetched = now;
                saveCache(cache);

                // Only log if location actually changed or it's a force refresh
                if (forceRefresh || !cache.location ||
                    cache.location.city !== location.city ||
                    cache.location.countryCode !== location.countryCode) {
                  debug(`Location: ${location.city}, ${location.countryCode}`);
                }

                resolve(location);
                return;
              }
            } catch (e) {
              debug('Failed to parse location data');
            }
          }

          // Return cached location if available, otherwise null
          resolve(cache.location);
        });
      } else {
        // Return cached location if available
        resolve(cache.location);
      }
    });
  });
}

// Get GPU information with utilization
async function getGPUInfo() {
  return new Promise((resolve) => {
    // Try NVIDIA first
    exec('nvidia-smi --query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu,utilization.memory --format=csv,noheader,nounits', (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.trim().split('\n');
        const gpus = lines.map(line => {
          const [name, memTotal, memUsed, memFree, gpuUtil, memUtil] = line.split(', ').map(s => s.trim());
          return {
            vendor: 'NVIDIA',
            model: name,
            memory: parseInt(memTotal),
            memoryUsed: parseInt(memUsed),
            memoryFree: parseInt(memFree),
            gpuUtilization: parseInt(gpuUtil),
            memoryUtilization: parseInt(memUtil)
          };
        });
        resolve(gpus.length > 0 ? gpus[0] : null);
        return;
      }

      // Try AMD
      exec('rocm-smi --showuse --showmeminfo vram --csv', (err2, stdout2) => {
        if (!err2 && stdout2) {
          const lines = stdout2.trim().split('\n');
          if (lines.length > 1) {
            resolve({
              vendor: 'AMD',
              model: 'AMD GPU',
              memory: 0,
              memoryUsed: 0,
              memoryFree: 0,
              gpuUtilization: 0,
              memoryUtilization: 0
            });
            return;
          }
        }

        resolve(null);
      });
    });
  });
}

// Calculate CPU usage
function getCPUUsage() {
  const cpus = os.cpus();

  let totalIdle = 0;
  let totalTick = 0;

  cpus.forEach(cpu => {
    for (const type in cpu.times) {
      totalTick += cpu.times[type];
    }
    totalIdle += cpu.times.idle;
  });

  const currentCpuInfo = { idle: totalIdle, total: totalTick };

  let usage = 0;
  if (previousCpuInfo) {
    const idleDiff = currentCpuInfo.idle - previousCpuInfo.idle;
    const totalDiff = currentCpuInfo.total - previousCpuInfo.total;
    usage = 100 - ~~(100 * idleDiff / totalDiff);
  }

  previousCpuInfo = currentCpuInfo;

  return {
    usage: Math.max(0, Math.min(100, usage)),
    cores: cpus.length,
    model: cpus[0].model,
    vendor: cpus[0].model.includes('Intel') ? 'Intel' :
            cpus[0].model.includes('AMD') ? 'AMD' :
            cpus[0].model.includes('Apple') ? 'Apple' : 'Unknown',
    speed: cpus[0].speed
  };
}

// Get memory information
function getMemoryInfo() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;

  return {
    total: Math.round(totalMem / 1024 / 1024 / 1024),
    used: Math.round(usedMem / 1024 / 1024 / 1024),
    free: Math.round(freeMem / 1024 / 1024 / 1024),
    percentage: Math.round((usedMem / totalMem) * 100)
  };
}

// Get comprehensive system metrics
async function getSystemMetrics() {
  const cpuInfo = getCPUUsage();
  const memoryInfo = getMemoryInfo();
  const gpuInfo = await getGPUInfo();

  return {
    cpu: cpuInfo,
    memory: memoryInfo,
    gpu: gpuInfo
  };
}

// Calculate uptime percentage
function calculateUptimePercentage() {
  const now = Date.now();
  const totalMonitorTime = now - monitorStartTime;

  // Start at 100% for the first 5 seconds
  if (totalMonitorTime < 5000) {
    return {
      percentage: 100,
      totalMonitorTime: Math.round(totalMonitorTime / 1000),
      swarmActiveTime: Math.round(swarmActiveTime / 1000),
      monitorStartTime: new Date(monitorStartTime).toISOString(),
      currentTime: new Date(now).toISOString()
    };
  }

  // Calculate availability percentage (time node has been active)
  const percentage = Math.round((swarmActiveTime / totalMonitorTime) * 100);

  return {
    percentage: Math.min(100, percentage),
    totalMonitorTime: Math.round(totalMonitorTime / 1000),
    swarmActiveTime: Math.round(swarmActiveTime / 1000),
    monitorStartTime: new Date(monitorStartTime).toISOString(),
    currentTime: new Date(now).toISOString()
  };
}

// Get system information (static data)
async function getSystemInfo() {
  const cpuInfo = getCPUUsage();
  const gpuInfo = await getGPUInfo();
  const totalMem = os.totalmem();

  return {
    cpu: {
      vendor: cpuInfo.vendor,
      model: cpuInfo.model,
      cores: cpuInfo.cores,
      speed: cpuInfo.speed
    },
    gpu: gpuInfo ? {
      vendor: gpuInfo.vendor,
      model: gpuInfo.model,
      memory: gpuInfo.memory
    } : null,
    memory: {
      total: Math.round(totalMem / 1024 / 1024 / 1024)
    },
    platform: os.platform(),
    hostname: os.hostname(),
    uptime: os.uptime()
  };
}

// Find last match in log content
function findLastMatch(content, patterns) {
  let lastMatch = null;
  let lastIndex = -1;

  patterns.forEach(pattern => {
    const matches = [...content.matchAll(new RegExp(pattern, 'gm'))];
    if (matches.length > 0) {
      const match = matches[matches.length - 1];
      if (match.index > lastIndex) {
        lastIndex = match.index;
        lastMatch = match;
      }
    }
  });

  return lastMatch ? { match: lastMatch[0], index: lastIndex } : null;
}

// Docker container management
let dockerContainerId = null;
let dockerContainerName = null;
let dockerLogStream = null;

// Find the Gensyn swarm Docker container
async function findSwarmContainer() {
  return new Promise((resolve) => {
    // Check for both swarm-cpu and swarm-gpu containers
    exec('docker ps --filter "name=swarm-cpu" --filter "name=swarm-gpu" --format "{{.ID}} {{.Names}} {{.Status}}"', (err, stdout) => {
      if (!err && stdout.trim()) {
        const lines = stdout.trim().split('\n');
        const firstContainer = lines[0].split(' ');
        const containerId = firstContainer[0];
        const containerName = firstContainer[1];
        debug(`Found swarm container: ${containerName} (${containerId})`);
        dockerContainerName = containerName; // Store the container name
        resolve(containerId);
      } else {
        // Try alternative: look for containers running from rl-swarm image
        exec('docker ps --format "{{.ID}} {{.Image}} {{.Names}}" | grep -E "rl-swarm|swarm"', (err2, stdout2) => {
          if (!err2 && stdout2.trim()) {
            const firstLine = stdout2.trim().split('\n')[0];
            const parts = firstLine.split(' ');
            const containerId = parts[0];
            const containerName = parts[2] || parts[1]; // Names is the third field
            debug(`Found swarm container by image: ${containerName} (${containerId})`);
            dockerContainerName = containerName; // Store the container name
            resolve(containerId);
          } else {
            resolve(null);
          }
        });
      }
    });
  });
}

// Check if Docker container is running and healthy
async function checkDockerContainer() {
  return new Promise(async (resolve) => {
    const containerId = await findSwarmContainer();
    if (!containerId) {
      resolve(false);
      return;
    }

    // Check container status
    exec(`docker inspect ${containerId} --format '{{.State.Status}}'`, (err, stdout) => {
      if (!err && stdout.trim() === 'running') {
        dockerContainerId = containerId;
        resolve(true);
      } else {
        dockerContainerId = null;
        resolve(false);
      }
    });
  });
}

// Enhanced process checking - now supports both native process and Docker
async function checkSwarmProcess() {
  return new Promise(async (resolve) => {
    // First, try Docker container
    const dockerRunning = await checkDockerContainer();
    if (dockerRunning) {
      debug('Swarm is running in Docker container');
      resolve(true);
      return;
    }

    // Fallback to native process check for backward compatibility
    exec('ps aux | grep -E "python.*train_single_gpu.*--config" | grep -v grep', (err, stdout) => {
      if (!err && stdout.trim().length > 0) {
        // Process exists, now check if it's actually healthy
        if (fs.existsSync(CONFIG.swarmLogFile)) {
          try {
            const stats = fs.statSync(CONFIG.swarmLogFile);
            const now = Date.now();
            const lastModified = stats.mtime.getTime();

            // If log hasn't been updated in 5 minutes, assume process is stuck
            if (now - lastModified > 300000) {
              debug('Process exists but log file is stale (>5 min)');
              resolve(false);
              return;
            }

            // Check log content for errors vs activity
            const logContent = fs.readFileSync(CONFIG.swarmLogFile, 'utf8');

            // Find last error and last activity
            const lastError = findLastMatch(logContent, ERROR_PATTERNS);
            const lastActivity = findLastMatch(logContent, ACTIVITY_PATTERNS);

            // If error is more recent than activity, node is offline
            if (lastError && (!lastActivity || lastError.index > lastActivity.index)) {
              const errorLines = logContent.substring(lastError.index).split('\n').slice(0, 3);
              warning(`Recent error detected: ${errorLines[0]}`);
              resolve(false);
              return;
            }

            // Check if training has started
            const hasTrainingStarted = ACTIVITY_PATTERNS.some(pattern => pattern.test(logContent));

            resolve(hasTrainingStarted);
          } catch (err) {
            error(`Error checking swarm status: ${err.message}`);
            resolve(false);
          }
        } else {
          // Process exists but no log file yet
          resolve(true);
        }
      } else {
        resolve(false);
      }
    });
  });
}

// Update uptime tracking
async function updateUptimeTracking() {
  const now = Date.now();
  const timeSinceLastCheck = now - lastSwarmCheck;

  const currentlyActive = await checkSwarmProcess();

  if (isSwarmActive) {
    swarmActiveTime += timeSinceLastCheck;
  }

  isSwarmActive = currentlyActive;
  lastSwarmCheck = now;

  return currentlyActive;
}

function parsePeerInfoFromLog(logContent) {
  // Try new emoji format first: 🐱 Hello 🐈 [trotting small zebra] 🦮 [Qmb7iaNjb636AT2TVxqgdbYzBrpnUWknPcvvu4URymcNey]
  const emojiMatch = logContent.match(/🐱\s*Hello\s*🐈\s*\[([^\]]+)\]\s*🦮\s*\[([^\]]+)\]/);
  if (emojiMatch) {
    return {
      PEER_NAME: emojiMatch[1].trim(),
      PEER_ID: emojiMatch[2].trim(),
      isComplete: true
    };
  }

  // Try old format: Hello [...] [...]
  const match = logContent.match(/Hello[^[]*\[([^\]]+)\][^[]*\[([^\]]+)\]/);
  if (match) {
    return {
      PEER_NAME: match[1].trim(),
      PEER_ID: match[2].trim(),
      isComplete: true
    };
  }

  // Try peer_id format
  const idMatch = logContent.match(/peer_id[:\s]+([A-Za-z0-9]+)/);
  if (idMatch) {
    return {
      PEER_ID: idMatch[1].trim(),
      PEER_NAME: null,
      isComplete: false
    };
  }

  // Try to find peer ID from "Peer ID [...] is already registered" message
  const registeredMatch = logContent.match(/Peer ID\s*\[([^\]]+)\]\s*is already registered/);
  if (registeredMatch) {
    return {
      PEER_ID: registeredMatch[1].trim(),
      PEER_NAME: null,
      isComplete: false
    };
  }

  return null;
}

// Watch Docker container logs
function watchDockerLogs(containerId) {
  debug(`Starting Docker log stream for container: ${containerId}`);

  // Get initial logs (last 100 lines)
  exec(`docker logs --tail 100 ${containerId}`, (err, stdout, stderr) => {
    if (!err) {
      const logContent = stdout + stderr;

      // Parse peer info from initial logs
      if (!peerInfo) {
        peerInfo = parsePeerInfoFromLog(logContent);
        if (peerInfo) {
          if (peerInfo.isComplete) {
            info(`Detected peer from Docker logs: ${peerInfo.PEER_NAME} (${peerInfo.PEER_ID})`);
          } else {
            info(`Detected peer ID from Docker logs: ${peerInfo.PEER_ID} (waiting for name...)`);
          }
          const cache = loadCache();
          cache.peerInfo = peerInfo;
          saveCache(cache);
        }
      }

      // Check current state
      const hasError = ERROR_PATTERNS.some(pattern => pattern.test(logContent));
      const hasActivity = ACTIVITY_PATTERNS.some(pattern => pattern.test(logContent));

      if (hasError) {
        const lastError = findLastMatch(logContent, ERROR_PATTERNS);
        const lastActivity = findLastMatch(logContent, ACTIVITY_PATTERNS);
        if (lastError && (!lastActivity || lastError.index > lastActivity.index)) {
          updateNodeStatus('offline');
        }
      } else if (hasActivity) {
        debug('Training activity detected in Docker logs');
        updateNodeStatus('online');
      }
    }
  });

  // Stream new logs
  const { spawn } = require('child_process');
  dockerLogStream = spawn('docker', ['logs', '-f', '--tail', '0', containerId]);

  let logBuffer = '';

  const processLogChunk = (data) => {
    logBuffer += data.toString();
    const lines = logBuffer.split('\n');
    logBuffer = lines.pop(); // Keep incomplete line in buffer

    for (const line of lines) {
      if (!line.trim()) continue;

      // Parse peer info if not found yet or incomplete
      if (!peerInfo || !peerInfo.isComplete) {
        const newPeerInfo = parsePeerInfoFromLog(line);
        if (newPeerInfo) {
          // Update peer info if we found more complete information
          if (!peerInfo || (newPeerInfo.isComplete && !peerInfo.isComplete)) {
            peerInfo = newPeerInfo;

            if (peerInfo.isComplete) {
              info(`Detected complete peer info from Docker logs: ${peerInfo.PEER_NAME} (${peerInfo.PEER_ID})`);
            } else {
              info(`Detected peer ID from Docker logs: ${peerInfo.PEER_ID} (waiting for name...)`);
            }

            const cache = loadCache();
            cache.peerInfo = peerInfo;
            saveCache(cache);

            if (peerInfo.isComplete && !nodeId) {
              registerOrUpdateNode();
            } else if (peerInfo.isComplete && nodeId && !peerInfo.nameUpdated) {
              // Update node name if we already have a nodeId but just found the complete name
              updateNodeName(peerInfo.PEER_NAME);
              peerInfo.nameUpdated = true; // Mark that we've updated the name

              // Update cache
              const cache = loadCache();
              cache.peerInfo = peerInfo;
              saveCache(cache);
            }
          }
        }
      }

      // Check for errors
      if (ERROR_PATTERNS.some(pattern => pattern.test(line))) {
        warning(`Error detected: ${line}`);
        updateNodeStatus('offline');
      }

      // Check for activity
      if (ACTIVITY_PATTERNS.some(pattern => pattern.test(line))) {
        debug('Training activity detected');
        updateNodeStatus('online');
      }

      // Detect completion
      if (line.includes('Training completed') || line.includes('Finished training')) {
        info('Training completed');
        updateNodeStatus('offline');
      }
    }
  };

  dockerLogStream.stdout.on('data', processLogChunk);
  dockerLogStream.stderr.on('data', processLogChunk);

  dockerLogStream.on('error', (err) => {
    error(`Docker log stream error: ${err.message}`);
  });

  dockerLogStream.on('close', (code) => {
    warning(`Docker log stream closed with code ${code}`);
    dockerLogStream = null;
  });
}

function watchSwarmLog() {
  try {
    // Check if we're using Docker
    if (dockerContainerId) {
      watchDockerLogs(dockerContainerId);
      return;
    }

    // Original file-based log watching
    const logFile = CONFIG.swarmLogFile;

    if (!fs.existsSync(logFile)) {
      debug(`Log file not found: ${logFile}`);
      const checkLogInterval = setInterval(() => {
        if (fs.existsSync(logFile)) {
          clearInterval(checkLogInterval);
          watchSwarmLog();
        }
      }, 5000);
      return;
    }

    const existingContent = fs.readFileSync(logFile, 'utf8');

    // Check current state in existing content
    const hasError = ERROR_PATTERNS.some(pattern => pattern.test(existingContent));
    const hasActivity = ACTIVITY_PATTERNS.some(pattern => pattern.test(existingContent));

    if (hasError) {
      debug('Errors detected in existing log');
      const lastError = findLastMatch(existingContent, ERROR_PATTERNS);
      const lastActivity = findLastMatch(existingContent, ACTIVITY_PATTERNS);

      // Only update to offline if error is more recent than activity
      if (lastError && (!lastActivity || lastError.index > lastActivity.index)) {
        updateNodeStatus('offline');
      }
    } else if (hasActivity) {
      debug('Training activity detected in existing log');
    }

    if (!peerInfo) {
      peerInfo = parsePeerInfoFromLog(existingContent);
      if (peerInfo) {
        if (peerInfo.isComplete) {
          info(`Detected peer from log: ${peerInfo.PEER_NAME} (${peerInfo.PEER_ID})`);
        } else {
          info(`Detected peer ID from log: ${peerInfo.PEER_ID} (waiting for name...)`);
        }

        // Save to cache
        const cache = loadCache();
        cache.peerInfo = peerInfo;
        saveCache(cache);
      }
    }

    lastLogPosition = existingContent.length;

    // Use fs.watchFile for more reliable file watching
    logWatcher = fs.watchFile(logFile, { interval: 1000 }, (curr, prev) => {
      if (curr.size > prev.size) {
        fs.readFile(logFile, 'utf8', (err, data) => {
          if (err) {
            error(`Error reading log: ${err.message}`);
            return;
          }

          const newContent = data.slice(lastLogPosition);
          lastLogPosition = data.length;

          if (!peerInfo || !peerInfo.isComplete) {
            const newPeerInfo = parsePeerInfoFromLog(newContent);
            if (newPeerInfo) {
              // Update peer info if we found more complete information
              if (!peerInfo || (newPeerInfo.isComplete && !peerInfo.isComplete)) {
                peerInfo = newPeerInfo;

                if (peerInfo.isComplete) {
                  info(`Detected complete peer info: ${peerInfo.PEER_NAME} (${peerInfo.PEER_ID})`);
                } else {
                  info(`Detected peer ID: ${peerInfo.PEER_ID} (waiting for name...)`);
                }

                // Save to cache
                const cache = loadCache();
                cache.peerInfo = peerInfo;
                saveCache(cache);

                // Only register if we're not already waiting for complete info in waitForSwarm
                if (peerInfo.isComplete && !nodeId) {
                  registerOrUpdateNode();
                } else if (peerInfo.isComplete && nodeId && !peerInfo.nameUpdated) {
                  // Update node name if we already have a nodeId but just found the complete name
                  updateNodeName(peerInfo.PEER_NAME);
                  peerInfo.nameUpdated = true; // Mark that we've updated the name

                  // Update cache
                  const cache = loadCache();
                  cache.peerInfo = peerInfo;
                  saveCache(cache);
                }
              }
            }
          }

          // Check for errors first
          if (ERROR_PATTERNS.some(pattern => pattern.test(newContent))) {
            const errorMatch = findLastMatch(newContent, ERROR_PATTERNS);
            if (errorMatch) {
              warning(`Error detected: ${errorMatch.match}`);
              updateNodeStatus('offline');
            }
          }

          // Check for activity
          if (ACTIVITY_PATTERNS.some(pattern => pattern.test(newContent))) {
            debug('Training activity detected');
            updateNodeStatus('online');
          }

          // Detect completion
          if (newContent.includes('Training completed') ||
              newContent.includes('Finished training')) {
            info('Training completed');
            updateNodeStatus('offline');
          }
        });
      } else if (curr.size < prev.size) {
        warning('Log file was truncated or rotated');
        lastLogPosition = 0;
      }
    });

    return logWatcher;
  } catch (err) {
    error(`Error in watchSwarmLog: ${err.message}`);
    error(`Stack trace: ${err.stack}`);
    // Don't crash, just continue without watching
    return null;
  }
}

function apiRequest(method, endpoint, data = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(CONFIG.dashboardUrl);
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: `/api${endpoint}`,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    };

    if (authToken) {
      options.headers['Cookie'] = `auth_token=${authToken}`;
    }

    const req = https.request(options, (res) => {
      let body = '';

      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        reject(new Error('Redirect detected. API endpoint may have changed.'));
        return;
      }

      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          if (res.headers['content-type'] && !res.headers['content-type'].includes('application/json')) {
            reject(new Error(`Invalid response type: ${res.headers['content-type']}`));
            return;
          }

          const response = JSON.parse(body);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            const cookies = res.headers['set-cookie'];
            if (cookies) {
              cookies.forEach(cookie => {
                const match = cookie.match(/auth_token=([^;]+)/);
                if (match) authToken = match[1];
              });
            }
            resolve(response);
          } else {
            reject(new Error(response.error || `HTTP ${res.statusCode}`));
          }
        } catch (err) {
          reject(new Error(`Failed to parse response: ${err.message}`));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.abort();
      reject(new Error('Request timeout'));
    });

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

function loadCredentials() {
  try {
    if (fs.existsSync(CONFIG.credentialsFile)) {
      const creds = JSON.parse(fs.readFileSync(CONFIG.credentialsFile, 'utf8'));
      return creds;
    }
  } catch (err) {
    // Ignore
  }
  return null;
}

async function authenticate() {
  const saved = loadCredentials();
  if (!saved) {
    error('No saved credentials found. Please run setup first.');
    return false;
  }

  try {
    info('Authenticating with Gensyn Hub...');
    const response = await apiRequest('POST', '/auth/login', {
      email: saved.email,
      password: saved.password,
      remember: true
    });

    if (response.success) {
      success('Authentication successful');
      info('Your node will be automatically added to your list of nodes');
      return true;
    }
  } catch (err) {
    error(`Authentication failed: ${err.message}`);
  }

  return false;
}

async function registerOrUpdateNode() {
  try {
    const cache = loadCache();

    // Check if we have a cached node ID
    if (cache.nodeId) {
      nodeId = cache.nodeId;
      info(`Using existing node ID: ${nodeId}`);

      // Try to update the existing node
      try {
        await updateNodeStatus('online', true); // Skip re-registration to avoid infinite loop
        return true;
      } catch (err) {
        warning(`Failed to update existing node: ${err.message}`);
        // Continue to register as new node
        nodeId = null;
        cache.nodeId = null;
        saveCache(cache);
      }
    }

    // Register new node
    return await registerNode();
  } catch (err) {
    error(`Failed to register/update node: ${err.message}`);
    return false;
  }
}

async function registerNode() {
  try {
    const systemInfo = await getSystemInfo();
    const isRunning = await checkSwarmProcess();
    const cache = loadCache();

    // Get location (use cached if available)
    const locationInfo = cache.location || await getLocationInfo();

    if (!peerInfo) {
      warning('No peer info available yet');
      return false;
    }

    const nodeData = {
      identifier: peerInfo.PEER_ID,
      customName: peerInfo.PEER_NAME || null, // Send null if no name available
      isMonitored: true,
      systemInfo: systemInfo,
      status: isRunning ? 'online' : 'offline',
      swarmType: 'MATH',
      ipAddress: locationInfo?.ip,
      runningProcess: dockerContainerName || null // Pass the container name
    };

    info('Registering node with dashboard...');
    const response = await apiRequest('POST', '/nodes/monitor/register', nodeData);

    if (response.success) {
      nodeId = response.node.id;
      success(`Node registered: ${peerInfo.PEER_NAME} (${nodeId})`);

      // Save node ID to cache
      cache.nodeId = nodeId;
      saveCache(cache);

      return true;
    }
  } catch (err) {
    error(`Failed to register node: ${err.message}`);
  }

  return false;
}

async function updateNodeStatus(status, skipReregistration = false) {
  if (!nodeId) return;

  try {
    await apiRequest('PUT', `/nodes/monitor/${nodeId}/status`, { status });
    debug(`Status updated to: ${status}`);
  } catch (err) {
    // Check if the error is due to node not found
    if (!skipReregistration && err.message && (err.message.includes('Node not found') || err.message.includes('404'))) {
      // Handle node not found error
      await handleNodeNotFound();
    } else {
      error(`Failed to update status: ${err.message}`);
    }
  }
}

async function sendUpdate() {
  if (!nodeId || !peerInfo) return;

  try {
    const isRunning = await updateUptimeTracking();
    const metrics = await getSystemMetrics();
    const cache = loadCache();
    const uptimeInfo = calculateUptimePercentage();

    // Use cached location
    const locationInfo = cache.location;

    const update = {
      status: isRunning ? 'online' : 'offline',
      peerInfo,
      timestamp: new Date().toISOString(),
      ipAddress: locationInfo?.ip,
      metrics: {
        cpu: {
          usage: metrics.cpu.usage,
          cores: metrics.cpu.cores,
          model: metrics.cpu.model,
          vendor: metrics.cpu.vendor,
          speed: metrics.cpu.speed
        },
        memory: {
          total: metrics.memory.total,
          used: metrics.memory.used,
          free: metrics.memory.free,
          percentage: metrics.memory.percentage
        },
        gpu: metrics.gpu ? {
          vendor: metrics.gpu.vendor,
          model: metrics.gpu.model,
          memory: metrics.gpu.memory,
          memoryUsed: metrics.gpu.memoryUsed,
          memoryFree: metrics.gpu.memoryFree,
          gpuUtilization: metrics.gpu.gpuUtilization,
          memoryUtilization: metrics.gpu.memoryUtilization
        } : null,
        uptime: uptimeInfo,
        location: locationInfo ? {
          country: locationInfo.country,
          countryCode: locationInfo.countryCode,
          region: locationInfo.region,
          city: locationInfo.city,
          lat: locationInfo.lat,
          lon: locationInfo.lon
        } : null
      }
    };

    await apiRequest('POST', `/nodes/monitor/${nodeId}/update`, update);

    updatesSent++;

    if (updatesSent % 10 === 0) {
      info(`Sent update #${updatesSent} - Status: ${update.status} | Uptime: ${uptimeInfo.percentage}%`);
    }

    // Display status line
    const statusIcon = isRunning ? '🟢' : '🔴';
    let statusLine = `${statusIcon} Status: ${isRunning ? 'ONLINE' : 'OFFLINE'} | `;
    statusLine += `Node: ${peerInfo.PEER_NAME} | `;
    statusLine += `Uptime: ${uptimeInfo.percentage}% | `;
    statusLine += `CPU: ${metrics.cpu.usage}% | `;
    statusLine += `RAM: ${metrics.memory.percentage}%`;

    if (metrics.gpu) {
      statusLine += ` | GPU: ${metrics.gpu.gpuUtilization}%`;
    }

    // Add location after memory
    if (locationInfo) {
      statusLine += ` | ${locationInfo.city}, ${locationInfo.countryCode}`;
    }

    process.stdout.write('\r' + ' '.repeat(100) + '\r');
    process.stdout.write(statusLine);
  } catch (err) {
    // Check if the error is due to node not found
    if (err.message && (err.message.includes('Node not found') || err.message.includes('404'))) {
      // Handle node not found error
      await handleNodeNotFound();
    } else {
      error(`Update failed: ${err.message}`);
    }
  }
}

async function updateNodeName(newPeerName) {
  if (!nodeId || !newPeerName) return;

  try {
    info(`Updating node name to: ${newPeerName}`);
    await apiRequest('PUT', `/nodes/monitor/${nodeId}`, {
      customName: newPeerName,
      peerName: newPeerName
    });
    success(`Node name updated to: ${newPeerName}`);
  } catch (err) {
    error(`Failed to update node name: ${err.message}`);
  }
}

async function notifyMonitorStop() {
  if (!nodeId) return;

  try {
    info('Notifying dashboard that monitor is stopping...');
    await apiRequest('POST', `/nodes/monitor/${nodeId}/stop`, {});
    success('Dashboard notified of monitor stop');
  } catch (err) {
    error(`Failed to notify monitor stop: ${err.message}`);
  }
}

// Check if another instance is running
function checkSingleInstance() {
  try {
    if (fs.existsSync(CONFIG.lockFile)) {
      const lockData = JSON.parse(fs.readFileSync(CONFIG.lockFile, 'utf8'));
      const lockPid = lockData.pid;

      // Check if the process is still running
      try {
        process.kill(lockPid, 0);
        // Process exists
        error(`Another monitor instance is already running (PID: ${lockPid})`);
        error('Please stop it first with: daemon.sh stop');
        process.exit(1);
      } catch (e) {
        // Process doesn't exist, remove stale lock
        warning('Found stale lock file, removing...');
        fs.unlinkSync(CONFIG.lockFile);
      }
    }

    // Create lock file
    fs.writeFileSync(CONFIG.lockFile, JSON.stringify({
      pid: process.pid,
      startTime: new Date().toISOString()
    }));

    // Remove lock on exit
    process.on('exit', () => {
      try {
        if (fs.existsSync(CONFIG.lockFile)) {
          const lockData = JSON.parse(fs.readFileSync(CONFIG.lockFile, 'utf8'));
          if (lockData.pid === process.pid) {
            fs.unlinkSync(CONFIG.lockFile);
          }
        }
      } catch (e) {
        // Ignore errors during cleanup
      }
    });
  } catch (err) {
    error(`Failed to check single instance: ${err.message}`);
  }
}

async function startMonitoring() {
  isMonitoring = true;

  info('Monitoring started - collecting live metrics every 5 seconds');

  // Initialize CPU tracking
  getCPUUsage();

  // Set up location refresh every 30 minutes
  locationFetchInterval = setInterval(async () => {
    debug('Refreshing location data...');
    await getLocationInfo(true); // Force refresh
  }, 30 * 60 * 1000);

  // Ensure update loop continues even if individual updates fail
  const updateInterval = setInterval(async () => {
    if (isMonitoring) {
      try {
        await sendUpdate();
      } catch (err) {
        error(`Update error: ${err.message}`);
      }
    }
  }, CONFIG.updateInterval);

  // Add heartbeat logging every minute
  const heartbeatInterval = setInterval(() => {
    if (isMonitoring) {
      const uptimeInfo = calculateUptimePercentage();
      console.log(''); // New line for clean display
      info(`Monitor heartbeat - Updates: ${updatesSent} | Uptime: ${uptimeInfo.percentage}% | Monitor Time: ${Math.round(uptimeInfo.totalMonitorTime / 60)}min | Swarm Time: ${Math.round(uptimeInfo.swarmActiveTime / 60)}min`);
    }
  }, 60000);

  // Graceful shutdown handlers
  const cleanup = async () => {
    console.log('\n');
    info('Shutting down monitor...');
    isMonitoring = false;
    clearInterval(updateInterval);
    clearInterval(heartbeatInterval);
    if (locationFetchInterval) {
      clearInterval(locationFetchInterval);
    }
    if (logWatcher) {
      fs.unwatchFile(CONFIG.swarmLogFile);
    }
    // Stop Docker log stream if active
    if (dockerLogStream) {
      debug('Stopping Docker log stream...');
      dockerLogStream.kill();
      dockerLogStream = null;
    }
    await updateNodeStatus('offline');
    await notifyMonitorStop();

    // Remove lock file
    try {
      if (fs.existsSync(CONFIG.lockFile)) {
        fs.unlinkSync(CONFIG.lockFile);
      }
    } catch (e) {
      // Ignore
    }

    success('Monitor stopped');
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  process.on('uncaughtException', (err) => {
    error(`Uncaught exception: ${err.message}`);
    error(err.stack);
  });

  process.on('unhandledRejection', (reason, promise) => {
    error(`Unhandled rejection at: ${promise}, reason: ${reason}`);
  });
}

async function waitForSwarm() {
  info('Waiting for RL-Swarm to start...');

  const checkInterval = setInterval(async () => {
    const isRunning = await checkSwarmProcess();

    if (isRunning) {
      // If using Docker, we need to start log watching after container is found
      if (dockerContainerId && !dockerLogStream) {
        watchSwarmLog();
      }

      // For file-based logs
      if (!dockerContainerId && fs.existsSync(CONFIG.swarmLogFile)) {
        if (!logWatcher) {
          watchSwarmLog();
        }

        const logContent = fs.readFileSync(CONFIG.swarmLogFile, 'utf8');
        if (!peerInfo) {
          peerInfo = parsePeerInfoFromLog(logContent);

          // Also check cache
          if (!peerInfo) {
            const cache = loadCache();
            peerInfo = cache.peerInfo;
          }
        }
      }

      // For Docker, peer info might be set by watchDockerLogs
      if (!peerInfo) {
        const cache = loadCache();
        peerInfo = cache.peerInfo;
      }

      if (peerInfo && !nodeId) {
        // If peer info is incomplete, wait for the emoji line
        if (!peerInfo.isComplete) {
          info(`Found peer ID: ${peerInfo.PEER_ID}, waiting for peer name...`);

          // Set up a timeout to proceed after 5 seconds even without peer name
          let waitingForName = true;
          const nameTimeout = setTimeout(() => {
            if (waitingForName) {
              warning('Timeout waiting for peer name, proceeding with registration...');
              waitingForName = false;
            }
          }, 5000);

          // Continue checking for complete peer info
          const nameCheckInterval = setInterval(async () => {
            const logContent = fs.existsSync(CONFIG.swarmLogFile)
              ? fs.readFileSync(CONFIG.swarmLogFile, 'utf8')
              : '';

            const completePeerInfo = parsePeerInfoFromLog(logContent);

            if (completePeerInfo && completePeerInfo.isComplete) {
              // Found complete peer info with name
              clearTimeout(nameTimeout);
              clearInterval(nameCheckInterval);
              clearInterval(checkInterval);
              waitingForName = false;

              peerInfo = completePeerInfo;
              info(`Found complete peer info: ${peerInfo.PEER_NAME} (${peerInfo.PEER_ID})`);

              // Save to cache
              const cache = loadCache();
              cache.peerInfo = peerInfo;
              saveCache(cache);

              if (await registerOrUpdateNode()) {
                startMonitoring();
              }
            } else if (!waitingForName) {
              // Timeout reached, proceed without peer name
              clearInterval(nameCheckInterval);
              clearInterval(checkInterval);

              info('Proceeding with registration without peer name...');

              if (await registerOrUpdateNode()) {
                startMonitoring();
              }
            }
          }, 500); // Check every 500ms for the emoji line

        } else {
          // Peer info is complete, proceed immediately
          clearInterval(checkInterval);
          info('Swarm detected! Checking registration...');

          if (await registerOrUpdateNode()) {
            startMonitoring();
          }
        }
      }
    }
  }, 2000);

  return checkInterval;
}

async function main() {
  console.log(`${colors.bright}${colors.cyan}╔═══════════════════════════════════════════════════════════════╗
║                   GensynHub Monitor v1.0.0                    ║
║           Live metrics monitoring for RL-Swarm nodes          ║
╚═══════════════════════════════════════════════════════════════╝${colors.reset}
`);

  // Check for single instance
  checkSingleInstance();

  info(`Monitoring RL-Swarm in: ${CONFIG.swarmDir}`);
  info(`Watching log file: ${CONFIG.swarmLogFile}`);
  info(`Features: Cached location, error detection, smart restart handling`);

  // Load cache and check for existing peer info
  const cache = loadCache();
  if (cache.peerInfo) {
    peerInfo = cache.peerInfo;
    info(`Loaded cached peer info: ${peerInfo.PEER_NAME} (${peerInfo.PEER_ID})`);
  }

  // Pre-fetch location in background (don't wait)
  getLocationInfo().catch(err => {
    debug(`Failed to pre-fetch location: ${err.message}`);
  });

  if (!await authenticate()) {
    error('Authentication required to continue');
    process.exit(1);
  }

  const isRunning = await checkSwarmProcess();

  if (isRunning) {
    info('Swarm process detected, checking logs...');
    isSwarmActive = true;

    // Handle Docker container logs
    if (dockerContainerId) {
      info(`Using Docker container: ${dockerContainerId}`);
      watchSwarmLog();

      // Give Docker logs a moment to initialize and parse peer info
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Check if peer info was found from Docker logs
      if (!peerInfo) {
        peerInfo = cache.peerInfo;
      }
    }
    // Handle file-based logs
    else if (fs.existsSync(CONFIG.swarmLogFile)) {
      const logContent = fs.readFileSync(CONFIG.swarmLogFile, 'utf8');

      // Check for cached peer info first
      if (!peerInfo) {
        peerInfo = cache.peerInfo || parsePeerInfoFromLog(logContent);
      }
    }

    if (peerInfo) {
      info(`Found peer info: ${peerInfo.PEER_NAME} (${peerInfo.PEER_ID})`);
      if (await registerOrUpdateNode()) {
        try {
          if (!dockerContainerId) {
            watchSwarmLog();
          }
          await startMonitoring();
        } catch (err) {
          error(`Error starting monitoring: ${err.message}`);
          error(`Stack trace: ${err.stack}`);
          process.exit(1);
        }
      } else {
        warning('Failed to register node');
        await waitForSwarm();
      }
    } else {
      warning('Swarm is running but peer info not found yet');
      await waitForSwarm();
    }
  } else {
    await waitForSwarm();
  }
}

if (require.main === module) {
  main().catch(err => {
    error(`Fatal error: ${err.message}`);
    process.exit(1);
  });
}
MONITOR_EOF

    chmod +x "$MONITOR_SCRIPT"
    success "Monitor script created"
}

# ============================================================================
# SETUP SCRIPT
# ============================================================================

create_setup_script() {
    SETUP_SCRIPT="$MONITOR_DIR/setup.sh"

    cat > "$SETUP_SCRIPT" << 'SETUP_EOF'
#!/bin/bash

MONITOR_DIR="$(dirname "$0")"
CREDENTIALS_FILE="$MONITOR_DIR/credentials.json"
GENSYN_HUB_URL="https://www.gensyn.info"

echo ""
echo "🔧 GensynHub Monitor Setup"
echo "========================="
echo ""

# Kill any existing monitors before setup
echo "Checking for existing monitor processes..."
pkill -f "node.*gensyn-monitor.js" 2>/dev/null || true
pkill -f "gensynhub-monitor.sh" 2>/dev/null || true
if [ -f "$MONITOR_DIR/monitor.pid" ]; then
    OLD_PID=$(cat "$MONITOR_DIR/monitor.pid" 2>/dev/null || echo "")
    if [ -n "$OLD_PID" ]; then
        kill -TERM "$OLD_PID" 2>/dev/null || true
        pkill -TERM -P "$OLD_PID" 2>/dev/null || true
    fi
    rm -f "$MONITOR_DIR/monitor.pid"
fi
sleep 1

if [ -f "$CREDENTIALS_FILE" ]; then
    echo "✅ Credentials found. Testing authentication..."

    AUTH_CHECK=$(cd "$MONITOR_DIR" && timeout 10 node -e "
        const fs = require('fs');
        const creds = JSON.parse(fs.readFileSync('$CREDENTIALS_FILE', 'utf8'));
        console.log('Credentials loaded for:', creds.email);
    " 2>&1)

    if [ $? -eq 0 ]; then
        echo "✅ Authentication is already configured"
        echo ""
        read -p "Do you want to reconfigure authentication? (y/N): " -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo ""
            echo "Ready to start monitor!"
            echo -e "Run: ${CYAN}$MONITOR_DIR/daemon.sh start${NC}"
            exit 0
        fi
    fi
fi

echo "Running authentication setup..."
echo ""

cat > "$MONITOR_DIR/auth-only.js" << 'EOJS'
const fs = require('fs');
const https = require('https');
const readline = require('readline');
const path = require('path');

const CONFIG = {
    dashboardUrl: process.env.GENSYN_HUB_URL || 'https://www.gensyn.info',
    credentialsFile: path.join(__dirname, 'credentials.json')
};

let authToken = null;

function apiRequest(method, endpoint, data = null) {
    return new Promise((resolve, reject) => {
        const url = new URL(CONFIG.dashboardUrl);
        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: `/api${endpoint}`,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        };

        if (authToken) {
            options.headers['Cookie'] = `auth_token=${authToken}`;
        }

        const req = https.request(options, (res) => {
            let body = '';

            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                reject(new Error('Redirect detected. API endpoint may have changed.'));
                return;
            }

            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    if (res.headers['content-type'] && !res.headers['content-type'].includes('application/json')) {
                        reject(new Error(`Invalid response type: ${res.headers['content-type']}`));
                        return;
                    }

                    const response = JSON.parse(body);
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        const cookies = res.headers['set-cookie'];
                        if (cookies) {
                            cookies.forEach(cookie => {
                                const match = cookie.match(/auth_token=([^;]+)/);
                                if (match) authToken = match[1];
                            });
                        }
                        resolve(response);
                    } else {
                        reject(new Error(response.error || `HTTP ${res.statusCode}`));
                    }
                } catch (err) {
                    reject(new Error(`Failed to parse response: ${err.message}`));
                }
            });
        });

        req.on('error', reject);
        req.setTimeout(30000, () => {
            req.abort();
            reject(new Error('Request timeout'));
        });

        if (data) {
            req.write(JSON.stringify(data));
        }

        req.end();
    });
}

async function promptCredentials() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        rl.question('Email: ', (email) => {
            rl.stdoutMuted = true;
            rl.question('Password: ', (password) => {
                rl.stdoutMuted = false;
                console.log();
                rl.close();
                resolve({ email, password });
            });

            rl._writeToOutput = function _writeToOutput(stringToWrite) {
                if (rl.stdoutMuted && stringToWrite.match(/^Password: /)) {
                    rl.output.write(stringToWrite);
                    rl.stdoutMuted = true;
                } else if (rl.stdoutMuted) {
                    rl.output.write('\x1b[2K\x1b[200D' + 'Password: ' + '*'.repeat(rl.line.length));
                } else {
                    rl.output.write(stringToWrite);
                }
            };
        });
    });
}

async function authenticate() {
    console.log('🔐 Gensyn Hub Authentication');
    console.log('');

    const credentials = await promptCredentials();

    try {
        console.log('\nAuthenticating with Gensyn Hub...');
        const response = await apiRequest('POST', '/auth/login', {
            email: credentials.email,
            password: credentials.password,
            remember: true
        });

        if (response.success) {
            console.log('✅ Authentication successful!');
            console.log('✅ Your node will be automatically added to your list of nodes');

            fs.writeFileSync(CONFIG.credentialsFile, JSON.stringify(credentials), {
                mode: 0o600
            });
            console.log('✅ Credentials saved');

            return true;
        }
    } catch (err) {
        console.error(`\n❌ Authentication failed: ${err.message}`);
        return false;
    }

    return false;
}

authenticate().then(success => {
    process.exit(success ? 0 : 1);
});
EOJS

cd "$MONITOR_DIR"
GENSYN_HUB_URL="$GENSYN_HUB_URL" node auth-only.js

if [ $? -eq 0 ]; then
    rm -f auth-only.js
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "You can now start the monitor in background:"
    echo "  $MONITOR_DIR/daemon.sh start"
    echo ""
    read -p "Start monitor now? (y/N): " -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        exec "$MONITOR_DIR/daemon.sh" start
    fi
else
    rm -f auth-only.js
    echo ""
    echo "❌ Setup failed. Please check your credentials and try again."
    exit 1
fi
SETUP_EOF

    chmod +x "$SETUP_SCRIPT"
}

# ============================================================================
# DAEMON CONTROL SCRIPT
# ============================================================================

create_daemon_script() {
    DAEMON_SCRIPT="$MONITOR_DIR/daemon.sh"

    cat > "$DAEMON_SCRIPT" << 'DAEMON_EOF'
#!/bin/bash

MONITOR_DIR="$(dirname "$0")"
PIDFILE="$MONITOR_DIR/monitor.pid"
LOGFILE="$MONITOR_DIR/monitor.log"
CREDENTIALS_FILE="$MONITOR_DIR/credentials.json"
LOCKFILE="$MONITOR_DIR/monitor.lock"
GENSYN_HUB_URL="https://www.gensyn.info"

# Kill any existing monitors before operations
cleanup_existing() {
    echo "Checking for existing monitor processes..."

    # Kill node processes
    pkill -f "node.*gensyn-monitor.js" 2>/dev/null && echo "Stopped existing node monitors"

    # Kill old shell monitors
    pkill -f "gensynhub-monitor.sh" 2>/dev/null && echo "Stopped old shell monitors"

    # Clean up lock file if process doesn't exist
    if [ -f "$LOCKFILE" ]; then
        LOCK_PID=$(cat "$LOCKFILE" | grep -o '"pid":[0-9]*' | cut -d: -f2 2>/dev/null || echo "")
        if [ -n "$LOCK_PID" ] && ! kill -0 "$LOCK_PID" 2>/dev/null; then
            rm -f "$LOCKFILE"
            echo "Removed stale lock file"
        fi
    fi

    sleep 1
}

start() {
    if [ ! -f "$CREDENTIALS_FILE" ]; then
        echo "❌ Not authenticated. Please run setup first:"
        echo "   $MONITOR_DIR/setup.sh"
        return 1
    fi

    # Clean up any existing monitors first
    cleanup_existing

    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "Monitor daemon is already running (PID: $(cat $PIDFILE))"
        return 1
    fi

    # Check for lock file from direct execution
    if [ -f "$LOCKFILE" ]; then
        LOCK_PID=$(cat "$LOCKFILE" | grep -o '"pid":[0-9]*' | cut -d: -f2 2>/dev/null || echo "")
        if [ -n "$LOCK_PID" ] && kill -0 "$LOCK_PID" 2>/dev/null; then
            echo "Monitor is already running directly (PID: $LOCK_PID)"
            echo "Stop it first with: $0 stop"
            return 1
        fi
    fi

    echo "Starting GensynHub Monitor v1.0.0 in background..."

    # Start monitor with auto-restart on failure
    nohup bash -c "
        while true; do
            env GENSYN_HUB_URL='$GENSYN_HUB_URL' node '$MONITOR_DIR/gensyn-monitor.js' >> '$LOGFILE' 2>&1
            EXIT_CODE=\$?
            if [ \$EXIT_CODE -eq 0 ]; then
                echo '[DAEMON] Monitor exited normally' >> '$LOGFILE'
                break
            else
                echo '[DAEMON] Monitor crashed with exit code \$EXIT_CODE, restarting in 5 seconds...' >> '$LOGFILE'
                sleep 5
            fi
        done
    " > /dev/null 2>&1 &

    echo $! > "$PIDFILE"

    # Wait a moment and verify it started
    sleep 2
    if kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "✅ Monitor started (PID: $(cat $PIDFILE))"
        echo "📄 Log file: $LOGFILE"
        echo ""
        echo "Commands:"
        echo "  View logs:  $0 logs"
        echo "  Stop:       $0 stop"
        echo "  Status:     $0 status"
    else
        echo "❌ Failed to start monitor"
        rm -f "$PIDFILE"
        return 1
    fi
}

stop() {
    # Clean up all monitor processes
    cleanup_existing

    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Stopping monitor daemon (PID: $PID)..."
            # Send SIGTERM to the wrapper process
            kill -TERM "$PID" 2>/dev/null
            # Also kill any child node processes
            pkill -TERM -P "$PID" 2>/dev/null
        fi
        rm -f "$PIDFILE"
    fi

    # Clean up lock file
    rm -f "$LOCKFILE" 2>/dev/null

    echo "✅ Monitor stopped"
}

status() {
    local running=false
    local pid=""

    # Check daemon PID
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        running=true
        pid=$(cat "$PIDFILE")
        echo "✅ Monitor daemon is running (PID: $pid)"
    fi

    # Check lock file
    if [ -f "$LOCKFILE" ]; then
        LOCK_PID=$(cat "$LOCKFILE" | grep -o '"pid":[0-9]*' | cut -d: -f2 2>/dev/null || echo "")
        if [ -n "$LOCK_PID" ] && kill -0 "$LOCK_PID" 2>/dev/null; then
            running=true
            echo "✅ Monitor is running directly (PID: $LOCK_PID)"
        fi
    fi

    # Check for any gensyn-monitor processes
    MONITOR_PIDS=$(pgrep -f "node.*gensyn-monitor.js" 2>/dev/null)
    if [ -n "$MONITOR_PIDS" ]; then
        running=true
        echo "✅ Found monitor processes: $MONITOR_PIDS"
    fi

    if [ "$running" = true ]; then
        echo "📄 Log file: $LOGFILE"
        echo ""

        if [ -f "$LOGFILE" ]; then
            echo "Recent logs:"
            tail -10 "$LOGFILE" | grep -E "(Sent update|Status:|ERROR:|WARNING:|Monitor heartbeat|Uptime:)"

            # Check if monitor is actually sending updates
            LAST_UPDATE=$(grep "Sent update\|Monitor heartbeat" "$LOGFILE" | tail -1)
            if [ -n "$LAST_UPDATE" ]; then
                echo ""
                echo "Last activity: $LAST_UPDATE"
            fi
        fi
    else
        echo "❌ Monitor is not running"
        [ -f "$PIDFILE" ] && rm -f "$PIDFILE"
        [ -f "$LOCKFILE" ] && rm -f "$LOCKFILE"
    fi
}

logs() {
    if [ -f "$LOGFILE" ]; then
        tail -f "$LOGFILE"
    else
        echo "No log file found"
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 2
        start
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "  start   - Start monitor in background"
        echo "  stop    - Stop monitor"
        echo "  restart - Restart monitor"
        echo "  status  - Check if monitor is running"
        echo "  logs    - Follow monitor logs"
        exit 1
        ;;
esac
DAEMON_EOF

    chmod +x "$DAEMON_SCRIPT"
}

# ============================================================================
# START SCRIPT
# ============================================================================

create_start_script() {
    LAUNCH_SCRIPT="$MONITOR_DIR/start.sh"

    cat > "$LAUNCH_SCRIPT" << EOF
#!/bin/bash
cd "$MONITOR_DIR"
exec node gensyn-monitor.js
EOF

    chmod +x "$LAUNCH_SCRIPT"
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================

main() {
    echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗
║                   GensynHub Monitor v${VERSION}                    ║
║           Live metrics monitoring for RL-Swarm nodes          ║
║                      Made with ❤️  by Koi                      ║
╚═══════════════════════════════════════════════════════════════╝${NC}
"

    log "Installing in: $SWARM_DIR"

    # Clean up any existing monitors BEFORE installation
    cleanup_existing_monitors

    if ! check_nodejs; then
        install_nodejs
    fi

    setup_directories

    create_monitor_script
    create_setup_script
    create_daemon_script
    create_start_script

    echo -e "\n${GREEN}${BOLD}✅ Installation complete!${NC}\n"

    echo "📋 What's new in v${VERSION}:"
    echo "  • Released support for GPU and CPU"
    echo "  • Automatic connection to the dashboard"
    echo ""

    echo "Next steps:"
    echo ""
    echo "1️⃣  First, run setup to authenticate:"
    echo -e "    ${CYAN}$MONITOR_DIR/setup.sh${NC}"
    echo ""
    echo "2️⃣  Then start the monitor in background:"
    echo -e "    ${CYAN}$MONITOR_DIR/daemon.sh start${NC}"
    echo ""
    echo "📌 Quick commands:"
    echo -e "  ${CYAN}$MONITOR_DIR/daemon.sh status${NC}  - Check status"
    echo -e "  ${CYAN}$MONITOR_DIR/daemon.sh logs${NC}    - View logs"
    echo -e "  ${CYAN}$MONITOR_DIR/daemon.sh stop${NC}    - Stop monitor"
    echo ""
    echo -e "${BOLD}Made with ❤️  by Koi${NC}"
    echo -e "${CYAN}⭐ Support the project: https://github.com/KoiIsARobot/GensynHub-Monitor${NC}"
    echo ""

    read -p "Run setup now to configure authentication? (Y/n): " -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        echo -e "\n${CYAN}Running setup...${NC}\n"
        exec "$MONITOR_DIR/setup.sh"
    fi
}

main
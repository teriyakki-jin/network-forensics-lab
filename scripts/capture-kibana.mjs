import { spawn } from 'node:child_process';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const output = path.join(root, 'assets', 'kibana-lens-dashboard.png');
const profile = path.join(root, `.capture-profile-${process.pid}`);
const chrome = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const externalPort = process.env.CHROME_DEBUG_PORT
  ? Number(process.env.CHROME_DEBUG_PORT)
  : null;
let port = externalPort;
const dashboardUrl =
  'http://127.0.0.1:5601/app/dashboards#/view/network-forensics-overview?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-2h,to:now))';

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForJson(url, attempts = 120) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
    } catch {
      // Chrome may still be starting.
    }
    await delay(500);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function waitForDebugPort(attempts = 120) {
  const activePortFile = path.join(profile, 'DevToolsActivePort');
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const [value] = (await readFile(activePortFile, 'utf8')).split(/\r?\n/);
      const parsed = Number(value);
      if (Number.isInteger(parsed) && parsed > 0) return parsed;
    } catch {
      // Chrome writes this file after its debugging endpoint is ready.
    }
    await delay(500);
  }
  throw new Error(`Timed out waiting for ${activePortFile}`);
}

async function capture() {
  await mkdir(path.dirname(output), { recursive: true });
  console.log('Starting headless Chrome');

  const browser = externalPort
    ? null
    : spawn(
        chrome,
        [
          '--headless=new',
          '--disable-gpu',
          '--disable-dev-shm-usage',
          '--no-first-run',
          '--no-default-browser-check',
          '--remote-debugging-port=0',
          `--user-data-dir=${profile}`,
          '--window-size=1600,1200',
          'about:blank',
        ],
        { stdio: 'ignore', windowsHide: true },
      );

  try {
    if (!externalPort) port = await waitForDebugPort();
    await waitForJson(`http://127.0.0.1:${port}/json/version`);
    console.log('Chrome DevTools is ready');
    const targets = await waitForJson(`http://127.0.0.1:${port}/json/list`);
    const target = targets.find((item) => item.type === 'page');
    if (!target?.webSocketDebuggerUrl) throw new Error('No debuggable Chrome page was found');

    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', reject, { once: true });
    });

    let sequence = 0;
    const pending = new Map();
    socket.addEventListener('message', ({ data }) => {
      const message = JSON.parse(data);
      if (!message.id || !pending.has(message.id)) return;
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    });

    const command = (method, params = {}) =>
      new Promise((resolve, reject) => {
        const id = ++sequence;
        pending.set(id, { resolve, reject });
        socket.send(JSON.stringify({ id, method, params }));
      });

    await command('Page.enable');
    await command('Runtime.enable');
    await command('Emulation.setDeviceMetricsOverride', {
      width: 1600,
      height: 1200,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await command('Page.navigate', { url: dashboardUrl });
    console.log('Waiting for the Kibana Lens dashboard');

    for (let attempt = 0; attempt < 45; attempt += 1) {
      await delay(1000);
      const result = await command('Runtime.evaluate', {
        expression:
          "document.readyState === 'complete' && document.body.innerText.includes('Network Forensics Lab')",
        returnByValue: true,
      });
      if (result.result?.value) break;
    }
    for (let attempt = 0; attempt < 45; attempt += 1) {
      await delay(1000);
      const result = await command('Runtime.evaluate', {
        expression:
          "document.body.innerText.includes('Unique count of scenario.keyword') && !document.querySelector('[data-test-subj=embeddablePanelLoading]')",
        returnByValue: true,
      });
      if (result.result?.value) break;
    }
    await delay(5000);
    await command('Runtime.evaluate', {
      expression:
        "[...document.querySelectorAll('button')].filter((button) => button.innerText.trim() === 'Dismiss').forEach((button) => button.click())",
    });
    await delay(2000);

    const screenshot = await command('Page.captureScreenshot', {
      format: 'png',
      captureBeyondViewport: false,
    });
    await writeFile(output, Buffer.from(screenshot.data, 'base64'));
    console.log(`Saved ${output}`);
    if (externalPort) await command('Browser.close').catch(() => {});
    socket.close();
  } finally {
    browser?.kill();
    await delay(500);
    if (!externalPort) {
      await rm(profile, { recursive: true, force: true }).catch(() => {});
    }
  }
}

capture().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

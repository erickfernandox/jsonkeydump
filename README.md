<h1>🔍 Jsonkeydump</h1>
<p><strong>Jsonkeydump</strong> is a Go tool designed to detect <strong>Open Redirect vulnerabilities via JavaScript sinks</strong>. It automatically extracts parameter names from HTML/JS content, injects a canary marker, and analyzes whether the reflected value flows into a redirect sink — enabling precise, low-noise detection of client-side open redirects.</p>
<p>Perfect for pentesters, bug hunters, and security researchers automating Open Redirect detection in web applications.</p>

<hr>

<h2>🚀 Features</h2>
<ul>
  <li><strong>Cluster bomb injection</strong>: injects a canary marker into up to 50 parameters simultaneously per request.</li>
  <li><strong>Variable-tracking analysis</strong>: detects which JS variable received the injected marker (Phase 1).</li>
  <li><strong>Sink detection</strong>: checks whether that variable flows into a known redirect sink like <code>location.href</code>, <code>window.open()</code>, <code>router.push()</code>, and more (Phase 2).</li>
  <li>Supports multiple extraction modes (JSON keys, HTML attributes, query params, JS vars).</li>
  <li>Supports multiple URLs via stdin.</li>
  <li>Multithreaded processing (configurable workers).</li>
  <li>TLS verification disabled by default for maximum coverage.</li>
</ul>

<hr>

<h2>⚙️ Installation</h2>

<h4>1. Clone the repository</h4>
<pre><code>git clone https://github.com/erickfernandox/jsonkeydump.git
cd jsonkeydump</code></pre>

<h4>or install via Go</h4>
<pre><code>go install github.com/erickfernandox/jsonkeydump@latest</code></pre>

<h4>2. Build</h4>
<pre><code>go build -o jsonkeydump main.go</code></pre>

<hr>

<h2>💡 Usage</h2>
<pre><code>cat urls.txt | ./jsonkeydump [flags]</code></pre>

<h3>Flags:</h3>
<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>-p</code></td>
      <td>Payload to inject in normal mode</td>
      <td><code>FUZZ</code></td>
    </tr>
    <tr>
      <td><code>-o</code></td>
      <td>Extraction mode (see below)</td>
      <td><code>0</code></td>
    </tr>
    <tr>
      <td><code>-t</code></td>
      <td>Number of concurrent threads</td>
      <td><code>15</code></td>
    </tr>
    <tr>
      <td><code>-scan</code></td>
      <td>Enable scan mode: cluster bomb → reflected var → sink detection</td>
      <td><code>false</code></td>
    </tr>
  </tbody>
</table>

<hr>

<h2>🔍 Extraction Modes (<code>-o</code>)</h2>
<table>
  <thead>
    <tr>
      <th>Mode</th>
      <th>Extracts from</th>
      <th>Example pattern recognized</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>0</code></td>
      <td>All modes combined (default)</td>
      <td>JSON keys + HTML attributes + query params + JS vars</td>
    </tr>
    <tr>
      <td><code>1</code></td>
      <td>JSON / JS object keys</td>
      <td><code>"redirect": "value"</code>, <code>'next' : '/home'</code></td>
    </tr>
    <tr>
      <td><code>2</code></td>
      <td><code>name</code> attribute in HTML inputs</td>
      <td><code>&lt;input name="returnUrl"&gt;</code></td>
    </tr>
    <tr>
      <td><code>3</code></td>
      <td><code>id</code> attribute in HTML elements</td>
      <td><code>&lt;div id="redirectTarget"&gt;</code></td>
    </tr>
    <tr>
      <td><code>4</code></td>
      <td>Query string parameters</td>
      <td><code>?next=value&amp;redirect=value</code></td>
    </tr>
    <tr>
      <td><code>5</code></td>
      <td>Bare JS variable assignments</td>
      <td><code>target = value</code></td>
    </tr>
  </tbody>
</table>

<hr>

<h2>🧠 How It Works</h2>

<h3>Normal Mode (URL generation)</h3>
<p>Jsonkeydump fetches each URL, extracts parameter names from the response body, and outputs new URLs with the payload injected into all discovered parameters.</p>
<pre><code>cat urls.txt | ./jsonkeydump -p "https://evil.com" -o 4</code></pre>
<p><strong>Output:</strong></p>
<pre><code>https://example.com/login?next=https://evil.com&redirect=https://evil.com</code></pre>

<h3>Scan Mode (<code>-scan</code>)</h3>
<p>This is the core detection engine. It runs a two-phase analysis per URL cluster:</p>

<p><strong>Phase 1 — Reflection detection:</strong> injects a canary marker (<code>https://PSCAN7x9zMARKER</code>) into up to 50 parameters at once. If the marker appears in the response body, Jsonkeydump identifies which JS variable received it by matching patterns like:</p>
<pre><code>var target = 'https://PSCAN7x9zMARKER'
redirectUrl: "https://PSCAN7x9zMARKER"
location = `https://PSCAN7x9zMARKER`</code></pre>

<p><strong>Phase 2 — Sink detection:</strong> checks whether the identified variable is passed to a known redirect sink. The following sinks are covered:</p>
<ul>
  <li><code>location.href =</code></li>
  <li><code>location.replace()</code></li>
  <li><code>location.assign()</code></li>
  <li><code>window.location =</code></li>
  <li><code>window.location.href =</code></li>
  <li><code>window.location.replace()</code></li>
  <li><code>window.open()</code></li>
  <li><code>window.navigate()</code></li>
  <li><code>document.location =</code></li>
  <li><code>navigate()</code></li>
  <li><code>router.push()</code></li>
  <li><code>router.replace()</code></li>
  <li><code>history.pushState()</code></li>
  <li><code>history.replaceState()</code></li>
</ul>

<pre><code>cat urls.txt | ./jsonkeydump -scan -t 20</code></pre>

<p><strong>Output:</strong></p>
<pre><code>[*] SCAN | cluster=50 | marker=https://PSCAN7x9zMARKER
[*] VULN=var→sink  SUSP=var reflects/indirect sink  INFO=raw reflection

[Vulnerable] - https://example.com/login?next=https://PSCAN7x9zMARKER&... - [var "next" → location.href =]
[Not Vulnerable] - https://example.com/page?ref=https://PSCAN7x9zMARKER&...
</code></pre>

<hr>

<h2>📌 Examples</h2>

<h4>Generate injection URLs (normal mode)</h4>
<pre><code>cat urls.txt | ./jsonkeydump -p "https://evil.com" -o 1</code></pre>

<h4>Full scan with 30 threads</h4>
<pre><code>cat urls.txt | ./jsonkeydump -scan -t 30</code></pre>

<h4>Combine with other recon tools</h4>
<pre><code>katana -u https://target.com -silent | ./jsonkeydump -scan -t 20</code></pre>

<hr>

<h2>🧵 Concurrency</h2>
<p>Uses configurable concurrent workers (default: <strong>15 threads</strong>). Each worker processes one URL at a time, injecting clusters of up to <strong>50 parameters per request</strong> to minimize HTTP round-trips while maximizing parameter coverage.</p>

<hr>

<h2>📌 Notes</h2>
<ul>
  <li>Cluster size is fixed at <strong>50 parameters per request</strong>.</li>
  <li>TLS certificate validation is <strong>disabled</strong> to allow scanning of hosts with self-signed certificates.</li>
  <li>HTTP timeout is set to <strong>15 seconds</strong> per request.</li>
  <li>Invalid URLs or HTTP errors are automatically skipped.</li>
  <li>Only accepts input via <strong>stdin</strong> (e.g. <code>cat</code>, <code>echo</code>, <code>katana</code>, etc.).</li>
  <li>In scan mode, a URL is only flagged <code>[Vulnerable]</code> when <strong>both</strong> a reflected variable <strong>and</strong> a redirect sink are confirmed.</li>
</ul>

<hr>

<h2>🛡️ Disclaimer</h2>
<p>This tool is intended for <strong>educational and authorized professional use only</strong>. Always obtain explicit permission before testing any system. Unauthorized use may violate applicable laws.</p>

<hr>

<h2>👨‍💻 Author</h2>
<p>Developed by <strong>erickfernandox</strong>.<br>
Contributions and pull requests are welcome!</p>

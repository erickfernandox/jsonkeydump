<h1>🧰 Jsonkeydump</h1>

<p><strong>Jsonkeydump</strong> is a Go tool that automatically extracts <strong>parameter names</strong> from HTML/JS content returned by URLs and builds URLs with injected payloads.</p>

<p>Perfect for pentesters, bug hunters, and security researchers who want to automate the detection of possible injection points in web applications.</p>

<hr>

<h2>🚀 Features</h2>
<ul>
  <li>Supports multiple extraction patterns (JSON keys, HTML inputs, IDs, query strings).</li>
  <li>Automatically builds URLs with payloads injected into found parameters.</li>
  <li>Supports multiple URLs via stdin.</li>
  <li>Multithreaded processing (15 workers).</li>
</ul>

<hr>

<h2>⚙️ Installation</h2>

<h4>1. Clone the repository</h4>
<pre><code>git clone https://github.com/erickfernandox/jsonkeydump.git
cd jsonkeydump
or
go install github.com/erickfernandox/jsonkeydump@latest
</code></pre>

<h4>2. Build</h4>
<pre><code>go build -o jsonkeydump main.go
</code></pre>

<hr>

<h2>💡 Usage</h2>
<pre><code>cat urls.txt | ./jsonkeydump -p "&lt;payload&gt;" -o &lt;mode&gt;
</code></pre>

<h3>Parameters:</h3>
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
      <td>Payload to inject into the found parameters</td>
      <td><code>FUZZ</code></td>
    </tr>
    <tr>
      <td><code>-o</code></td>
      <td>Extraction mode (see below)</td>
      <td><code>1</code></td>
    </tr>
  </tbody>
</table>

<hr>

<h2>🔍 Extraction Modes (<code>-o</code>)</h2>
<table>
  <thead>
    <tr>
      <th>Mode</th>
      <th>Extracts from...</th>
      <th>Recognized example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1</td>
      <td>JSON or JS keys with single or double quotes</td>
      <td><code>"param": "value"</code>, <code>'id' : '1'</code></td>
    </tr>
    <tr>
      <td>2</td>
      <td><code>name</code> attribute in HTML inputs</td>
      <td><code>&lt;input name="email"&gt;</code></td>
    </tr>
    <tr>
      <td>3</td>
      <td><code>id</code> attribute in HTML elements</td>
      <td><code>&lt;div id="container"&gt;</code></td>
    </tr>
    <tr>
      <td>4</td>
      <td>Query string parameters</td>
      <td><code>?a=1&amp;b=2</code> extracts <code>a</code> and <code>b</code></td>
    </tr>
  </tbody>
</table>

<hr>

<h2>📌 Example</h2>
<pre><code>cat urls.txt | ./jsonkeydump -p "&lt;script&gt;alert(1)&lt;/script&gt;" -o 1
</code></pre>

<p><strong>Output:</strong></p>
<pre><code>https://example.com?param1=&lt;script&gt;alert(1)&lt;/script&gt;&amp;param2=&lt;script&gt;alert(1)&lt;/script&gt;
</code></pre>

<hr>

<h2>🧵 Concurrency</h2>
<p>Uses <strong>15 concurrent workers</strong> to speed up processing of multiple URLs.</p>

<hr>

<h2>📌 Notes</h2>
<ul>
  <li>Limit of <strong>100 parameters per URL</strong>.</li>
  <li>Invalid URLs or HTTP errors are automatically skipped.</li>
  <li>Only accepts input via <strong>stdin</strong> (e.g. <code>cat</code>, <code>xargs</code>, etc.).</li>
</ul>

<hr>

<h2>🛡️ Disclaimer</h2>
<p>This tool is intended for <strong>educational and authorized professional use only</strong>. Misuse may violate legal or ethical policies.</p>

<hr>

<h2>👨‍💻 Author</h2>
<p>Developed by erickfernandox.<br>
Contributions are welcome!</p>

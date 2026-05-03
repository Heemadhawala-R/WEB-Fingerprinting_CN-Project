# WEB SERVER FINGERPRINTING TOOL WITH SSL CERTIFICATE DOWNLOAD

#t is a network analysis program that connects to websites and identifies the type of 
# web server they use, their security (SSL), and measures response time 

# -------------------------------
#How does it work 
# -------------------------------
# #1)User Input: You provide a list of websites to scan.
# 2)Banner Grabbing: The program sends an HTTP request and reads the response headers.
# 3)Server Analysis: Based on headers, the program guesses the operating system and server type.
# 4)SSL Check: Verifies if HTTPS is enabled and reads certificate info.
# 5)Latency Measurement: Records how fast the server responds.
# 6)Multi-threading: Scans multiple websites at the same time for efficiency.
# 7)Result Storage: Saves results in a text file and calculates performance metrics like throughput and accuracy

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

# Global performance tracking
request_count = 0
identified_servers = 0
total_scans = 0

start_global = time.time()


# -------------------------------
# Banner Grabbing (HTTP only)
# -------------------------------
def grab_banner(host, port):
    try:
        s = socket.socket()  # Creates communication channel between your system and server
        s.settimeout(3)
        s.connect((host, port))

        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        s.send(request.encode())

        response = s.recv(4096).decode(errors="ignore")
        s.close()

        headers = response.split("\r\n\r\n")[0]
        return headers

    except socket.timeout:
        return "Connection Timeout"
    except ConnectionRefusedError:
        return "Connection Refused"
    except Exception as e:
        return f"Error: {str(e)}"


# -------------------------------
# Extract Server Info
# -------------------------------
def extract_server_info(response):
    if not response or "Error" in response:
        return response

    for line in response.split("\n"):
        if "Server:" in line:
            return line.strip()

    return "Server header not found"



#🔹 How SSL works (simplified)
# 1)Client connects → asks server for certificate
# 2)Server sends SSL certificate
#3)Certificate contains: Domain name ,Issuer (who signed it),Expiration date
#Client verifies certificate → if valid → secure encrypted channel established

#🔹 Types of SSL Certificates
#Domain Validation (DV) – Simple, cheap, verifies domain only
#Organization Validation (OV) – Verifies domain + organization info
#Extended Validation (EV) – Strictest, shows company name in browser


# -------------------------------
# SSL Check (HTTPS)
# -------------------------------
def check_ssl(host, port=443):
    try:
        context = ssl.create_default_context()
        #a context is like a settings container for secure connections.
        with socket.create_connection((host, port), timeout=3) as sock:   #with → ensures socket closes automatically
                                                #Creates a TCP connection to the server
            with context.wrap_socket(sock, server_hostname=host) as ssock:  #Wraps the plain socket in SSL
                cert = ssock.getpeercert()
                issuer = cert.get('issuer')

                # ✅ Call the function to download/save certificate
                download_ssl_certificate(host, ssock)

                return f"SSL Enabled | Issuer: {issuer}"

    except ssl.SSLError:
        return "SSL Handshake Failed"
    except socket.timeout:
        return "SSL Timeout"
    except Exception:
        return "No SSL / SSL Error"


# -------------------------------
# Download SSL Certificate (NEW FUNCTION)
# -------------------------------
def download_ssl_certificate(host, ssock, filename=None):
    """
    Downloads the SSL certificate from a wrapped socket (ssock)
    and saves it as PEM format locally.
    """
    if not filename:
        filename = f"{host.replace('.', '_')}_cert.pem"

    try:
        der_cert = ssock.getpeercert(binary_form=True)  # Get cert in binary DER
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)   # Convert to PEM

        with open(filename, "w") as f:
            f.write(pem_cert)

        print(f"✅ Certificate saved as: {filename}")

    except Exception as e:
        print(f"❌ Failed to download certificate for {host}: {e}")


# -------------------------------
# Server Analysis.   Determines server type from HTTP header
# -------------------------------
def analyze_server(server_info):
    if not server_info:
        return "Unknown"

    if "Apache" in server_info:
        return "Likely Linux (Apache)"
    elif "nginx" in server_info:
        return "High-performance server (nginx)"
    elif "IIS" in server_info:
        return "Likely Windows (IIS)"
    else:
        return "Unknown server type"


# -------------------------------
# Fingerprint Function
# -------------------------------
def fingerprint(host):
    global request_count, identified_servers, total_scans

    request_count += 1
    total_scans += 1
    host = host.strip()

    if not host:
        print("Invalid host input\n")
        return

    start_time = time.time()
    result = f"\n🔍 Scanning: {host}\n"

    # HTTP info
    http_response = grab_banner(host, 80)
    http_info = extract_server_info(http_response)
    analysis = analyze_server(http_info)

    result += f"HTTP Info: {http_info}\n"
    result += f"Analysis: {analysis}\n"

    # Accuracy tracking
    if "Unknown" not in analysis:
        identified_servers += 1

    # SSL info + download certificate
    result += f"HTTPS Info: Handled via SSL\n"
    result += f"SSL Info: {check_ssl(host)}\n"

    latency = time.time() - start_time
    result += f"Latency: {latency:.4f} sec\n"

    print(result)

    # Save results to file
    with open("results.txt", "a") as f:
        f.write(result + "\n")


# -------------------------------
# Multi-threading
# -------------------------------
def scan_multiple(hosts):
    print(f"\nScanning {len(hosts)} hosts concurrently...\n")
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(fingerprint, hosts)


# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    targets = [t.strip() for t in input("Enter websites (comma separated): ").split(",")]
    scan_multiple(targets)

    end_global = time.time()
    total_time = end_global - start_global

    # Throughput
    if total_time > 0:
        throughput = request_count / total_time
        print(f"\nThroughput: {throughput:.2f} requests/sec")

    # Accuracy Evaluation
    if total_scans > 0:
        accuracy = (identified_servers / total_scans) * 100
        print("\nAccuracy Evaluation")
        print("--------------------")
        print(f"Total Servers Scanned : {total_scans}")
        print(f"Successfully Identified: {identified_servers}")
        print(f"Detection Accuracy    : {accuracy:.2f}%")
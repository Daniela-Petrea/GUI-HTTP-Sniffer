import re
import threading

from pynput import keyboard

import parser
import sniffer as sf


def start(filter_thread_status=0):
    print('\nRunning sniffer thread\n')
    print("FILTER " + str(filter_thread_status))
    while sniffer_thread_running:
        sniffer = sf.Sniffer()
        sniffer.initialize()
        raw_data = sniffer.start()
        ipv4_header = parser.ipv4_unpack(raw_data[0][0:20])
        if ipv4_header["Protocol"] == 6:
            tcp_header = parser.tcp_unpack(raw_data[0][20:40])
            if tcp_header["Source port"] == 80 or tcp_header["Destination port"] == 80:
                http_decoded = parser.http_decode(raw_data[0][40:])
                if re.search(r"H+.*\s*T+.*\s*T+.*\s*P", http_decoded):
                    request = ""
                    if re.search(r"GET", http_decoded.strip()):
                        request = "GET"
                    if re.search(r"POST", http_decoded.strip()):
                        request = "POST"
                    if re.search(r"PUT", http_decoded.strip()):
                        request = "PUT"
                    if re.search(r"HEAD", http_decoded.strip()):
                        request = "HEAD"
                    if re.search(r"DELETE", http_decoded.strip()):
                        request = "DELETE"
                    if filter_thread_status == 0:
                        try:
                            f = open("status.txt", "a")
                            f.write("source_address_IP=\"" + str(ipv4_header["Source address"]) + "\" ")
                            f.write("destination_address_IP=\"" + str(ipv4_header["Destination address"]) + "\" ")
                            f.write("protocol=\"" + str(ipv4_header["Protocol"]) + "\" ")
                            f.write("source_port=\"" + str(tcp_header["Source port"]) + "\" ")
                            f.write("destination_port=\"" + str(tcp_header["Destination port"]) + "\" ")
                            f.write("HTTP_response_status=\"" + request + "\" ")
                            f.write("HTTP_header=\"" + http_decoded.strip() + "\" \n\n\n")
                            f.close()
                            f = open("status.txt", "r")
                            for line in f:
                                print(line.strip())
                            f.close()
                        except FileNotFoundError:
                            print(f"Sorry, the status.txt does not exist.")
                    elif (filter_thread_status == 1 and request == "GET") or (
                            filter_thread_status == 2 and request == "POST") or (
                            filter_thread_status == 3 and request == "PUT") or (
                            filter_thread_status == 4 and request == "HEAD") or (
                            filter_thread_status == 5 and request == "DELETE"):
                        try:
                            f = open("status.txt", "a")
                            f.write("source_address_IP=\"" + str(ipv4_header["Source address"]) + "\" ")
                            f.write("destination_address_IP=\"" + str(ipv4_header["Destination address"]) + "\" ")
                            f.write("protocol=\"" + str(ipv4_header["Protocol"]) + "\" ")
                            f.write("source_port=\"" + str(tcp_header["Source port"]) + "\" ")
                            f.write("destination_port=\"" + str(tcp_header["Destination port"]) + "\" ")
                            f.write("HTTP_response_status=\"" + request + "\" ")
                            f.write("HTTP_header=\"" + http_decoded.strip() + "\" *\n\n\n")
                            f.close()
                            f = open("status.txt", "r")
                            for line in f:
                                print(line.strip())
                            f.close()
                        except FileNotFoundError:
                            return "Sorry, the file status.txt does not exist."
    print('\nExiting sniffer thread\n')


def key_press(key):
    global sniffer_thread_running
    global sniffer_thread
    global filter_thread
    if key == keyboard.KeyCode(char='s'):
        if not sniffer_thread_running:
            sniffer_thread = threading.Thread(target=start, args=(filter_thread,))
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            open("status.txt", "w").close()
            sniffer_thread_running = False
            sniffer_thread.join()
    if key == keyboard.KeyCode(char='e'):
        return False
    if key == keyboard.KeyCode(char='0'):
        if sniffer_thread_running:
            sniffer_thread_running = False
            sniffer_thread.join()
            open("status.txt", "w").close()
            filter_thread = 0
            sniffer_thread = threading.Thread(target=start, args=(filter_thread,))
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            filter_thread = 0
    if key == keyboard.KeyCode(char='1'):
        if sniffer_thread_running:
            sniffer_thread_running = False
            sniffer_thread.join()
            open("status.txt", "w").close()
            filter_thread = 1
            sniffer_thread = threading.Thread(target=start, args=(filter_thread,))
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            filter_thread = 1
    if key == keyboard.KeyCode(char='2'):
        if sniffer_thread_running:
            sniffer_thread_running = False
            sniffer_thread.join()
            open("status.txt", "w").close()
            filter_thread = 2
            sniffer_thread = threading.Thread(target=start, args=(filter_thread,))
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            filter_thread = 2
    if key == keyboard.KeyCode(char='3'):
        if sniffer_thread_running:
            sniffer_thread_running = False
            sniffer_thread.join()
            open("status.txt", "w").close()
            filter_thread = 3
            sniffer_thread = threading.Thread(target=start, args=(filter_thread,))
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            filter_thread = 3
    if key == keyboard.KeyCode(char='4'):
        if sniffer_thread_running:
            sniffer_thread_running = False
            sniffer_thread.join()
            open("status.txt", "w").close()
            filter_thread = 4
            sniffer_thread = threading.Thread(target=start, args=(filter_thread,))
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            filter_thread = 4
    if key == keyboard.KeyCode(char='5'):
        if sniffer_thread_running:
            sniffer_thread_running = False
            sniffer_thread.join()
            open("status.txt", "w").close()
            filter_thread = 5
            sniffer_thread = threading.Thread(target=start, args=(filter_thread,))
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            filter_thread = 5


if __name__ == "__main__":
    sniffer_thread_running = False
    sniffer_thread = None
    filter_thread = 0
    while True:
        try:
            print("Welcome to GUI HTTP Sniffer! ")
            print("Choose an option: ")
            print("Press s to start/stop thread")
            print("Press 0 to see all HTTP requests")
            print("Press 1 to see HTTP requests with GET HTTP request method")
            print("Press 2 to see HTTP requests with POST HTTP request method")
            print("Press 3 to see HTTP requests with PUT HTTP request method")
            print("Press 4 to see HTTP requests with HEAD HTTP request method")
            print("Press 5 to see HTTP requests with DELETE HTTP request method")
            print("Press e to exit")
            keyboard_listener = keyboard.Listener(on_press=key_press)
            keyboard_listener.start()
            keyboard_listener.join()
        except KeyboardInterrupt:
            open("status.txt", "w").close()
            print("\nStopped by Ctrl+C\n")
            break
        else:
            open("status.txt", "w").close()
            print("\nStopped by key e\n")
            break
        finally:
            if sniffer_thread_running:
                sniffer_thread_running = False

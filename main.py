from pynput import keyboard
import sniffer as sf
import parser
import threading
import re


def start(filter_thread_status=0):
    print('\nRunning sniffer thread\n')
    print("FILTER " + str(filter_thread_status))
    while sniffer_thread_running:
        sniffer = sf.Sniffer()
        sniffer.initialize()
        raw_data = sniffer.start()
        ipv4_header = parser.ipv4_unpack(raw_data[0][14:34])
        if ipv4_header["Protocol"] == 6:
            tcp_header = parser.tcp_unpack(raw_data[0][34:54])
            if tcp_header["Source port"] == 80 or tcp_header["Destination port"] == 80:
                http_decoded = parser.http_decode(raw_data[0][54:])
                if re.search(r"H+.*\s*T+.*\s*T+.*\s*P", http_decoded):
                    response_status = ""
                    if re.search(r"\d{3}", http_decoded.strip()):
                        response_status = (re.search(r"\d{3}", http_decoded.strip())).group(0)
                    if filter_thread_status == 0:
                        try:
                            f = open("status.txt", "a")
                            f.write("source_address_IP=\"" + str(ipv4_header["Source address"]) + "\" ")
                            f.write("destination_address_IP=\"" + str(ipv4_header["Destination address"]) + "\" ")
                            f.write("protocol=\"" + str(ipv4_header["Protocol"]) + "\" ")
                            f.write("source_port=\"" + str(tcp_header["Source port"]) + "\" ")
                            f.write("destination_port=\"" + str(tcp_header["Destination port"]) + "\" ")
                            f.write("HTTP_response_status=\"" + response_status + "\" ")
                            f.write("HTTP_header=\"" + http_decoded.strip() + "\" *\n\n\n")
                            f.close()
                            f = open("status.txt", "r")
                            for line in f:
                                print(line.strip())
                            f.close()
                            # print("Source address IP: ", ipv4_header["Source address"])
                            # print("Destination address IP: ", ipv4_header["Destination address"])
                            # print("Protocol: ", ipv4_header["Protocol"])
                            # print("Source Port: ", tcp_header["Source port"])
                            # print("Destination port: ", tcp_header["Destination port"])
                            # print("HTTP header: ", http_decoded.strip())
                            # print("\n\n\n")
                        except FileNotFoundError:
                            print(f"Sorry, the status.txt does not exist.")
                    elif int(response_status[0]) == filter_thread_status:
                        try:
                            #regex = ""
                            f = open("status.txt", "a")
                            f.write("source_address_IP=\"" + str(ipv4_header["Source address"]) + "\" ")
                            f.write("destination_address_IP=\"" + str(ipv4_header["Destination address"]) + "\" ")
                            f.write("protocol=\"" + str(ipv4_header["Protocol"]) + "\" ")
                            f.write("source_port=\"" + str(tcp_header["Source port"]) + "\" ")
                            f.write("destination_port=\"" + str(tcp_header["Destination port"]) + "\" ")
                            f.write("HTTP_response_status=\"" + response_status + "\" ")
                            f.write("HTTP_header=\"" + http_decoded.strip() + "\" *\n\n\n")
                            f.close()
                            f = open("status.txt", "r")
                            # if filter_thread_status == 1:
                            #     regex = r"1\d{2}"
                            # elif filter_thread_status == 2:
                            #     regex = r"2\d{2}"
                            # elif filter_thread_status == 3:
                            #     regex = r"3\d{2}"
                            # elif filter_thread_status == 4:
                            #     regex = r"4\d{2}"
                            # elif filter_thread_status == 5:
                            #     regex = r"5\d{2}"
                            for line in f:
                                # if re.search("HTTP_response_status=\"" + regex + "\"", line.strip()):
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
            print("\033[1m Welcome to GUI HTTP Sniffer! \033[0m")
            print("\033[1;32m Choose an option: \033[0m")
            print("\033[1;32m Press s to start/stop thread \033[0m")
            print("\033[1;32m Press 0 to see all HTTP requests \033[0m")
            print("\033[1;32m Press 1 to see HTTP requests with informational responses (100 – 199) \033[0m")
            print("\033[1;32m Press 2 to see HTTP requests with successful responses (200 – 299) \033[0m")
            print("\033[1;32m Press 3 to see HTTP requests with redirection messages (300 – 399) \033[0m")
            print("\033[1;32m Press 4 to see HTTP requests with client error responses (400 – 499) \033[0m")
            print("\033[1;32m Press 5 to see HTTP requests with server error responses (500 – 599) \033[0m")
            print("\033[1;32m Press e to exit \033[0m")
            keyboard_listener = keyboard.Listener(on_press=key_press)
            keyboard_listener.start()
            keyboard_listener.join()
        except KeyboardInterrupt:
            open("status.txt", "w").close()
            print("\n\033[1mStopped by Ctrl+C\n\033[0m")
            break
        else:
            open("status.txt", "w").close()
            print("\n\033[1mStopped by key e\n\033[0m")
            break
        finally:
            if sniffer_thread_running:
                sniffer_thread_running = False

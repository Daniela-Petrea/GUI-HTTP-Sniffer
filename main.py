from pynput import keyboard
import sniffer as sf
import parser
import threading
import re


def start():
    print('\nRunning sniffer thread\n')
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
                    print("Source address IP: ", ipv4_header["Source address"])
                    print("Destination address IP: ", ipv4_header["Destination address"])
                    print("Protocol: ", ipv4_header["Protocol"])
                    print("Source Port: ", tcp_header["Source port"])
                    print("Destination port: ", tcp_header["Destination port"])
                    print("HTTP header: ", http_decoded.strip())
                    print("\n\n\n")
    print('\nExiting sniffer thread\n')


def key_press(key):
    global sniffer_thread_running
    global sniffer_thread
    if key == keyboard.KeyCode(char='1'):
        if not sniffer_thread_running:
            sniffer_thread = threading.Thread(target=start)
            sniffer_thread_running = True
            sniffer_thread.start()
        else:
            sniffer_thread_running = False
            sniffer_thread.join()
    if key == keyboard.KeyCode(char='5'):
        return False


if __name__ == "__main__":
    sniffer_thread_running = False
    sniffer_thread = None
    try:
        print("\033[1m Welcome to GUI HTTP Sniffer! \033[0m")
        print("\033[1;32m Choose an option: \033[0m")
        print("\033[1;32m Press 1 to start/stop thread \033[0m")
        print("\033[1;32m Press 2 to filter HTTP request by HTTP request methods \033[0m")
        print("\033[1;32m Press 5 to exit \033[0m")
        keyboard_listener = keyboard.Listener(on_press=key_press)
        keyboard_listener.start()
        keyboard_listener.join()
    except KeyboardInterrupt:
        print("\n\033[1mStopped by Ctrl+C\n\033[0m")
    else:
        print("\n\033[1mStopped by key 5\n\033[0m")
    finally:
        if sniffer_thread_running:
            sniffer_thread_running = False

import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, TCP, IP

OUTPUT_FILE = "sniffed_packets.txt"

def packet_sniff(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto if IP in packet else "N/A"
        payload = str(packet[TCP].payload)

        output_string = f"Source IP: {src_ip}\n"
        output_string += f"Destination IP: {dst_ip}\n"
        output_string += f"Source Port: {src_port}\n"
        output_string += f"Destination Port: {dst_port}\n"
        output_string += f"Protocol: {protocol}\n"
        output_string += f"Payload: {payload[:50]}...\n"

        output_text.insert(tk.END, output_string)

        # Save packet information to file
        with open(OUTPUT_FILE, "a") as f:
            f.write(output_string)
            f.write("\n\n")

def start_sniffing():
    try:
        output_text.delete(1.0, tk.END)
        sniff(filter="tcp", prn=packet_sniff, store=0, count=10)
        messagebox.showinfo("Info", "Packet sniffing completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def create_gui():
    root = tk.Tk()
    root.title("Packet Sniffer")
    root.geometry("600x400")

    disclaimer = "This packet sniffer tool is intended for educational and ethical purposes only.\nUnauthorized use, distribution, or modification of this tool is strictly prohibited."
    disclaimer_label = tk.Label(root, text=disclaimer, wraplength=550, pady=10)
    disclaimer_label.pack()

    terms_button = tk.Button(root, text="View Terms and Conditions", command=view_terms)
    terms_button.pack()

    accept_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
    accept_button.pack(pady=10)

    global output_text
    output_text = tk.Text(root, height=15, width=70, wrap=tk.WORD)
    output_text.pack()

    root.mainloop()

def view_terms():
    messagebox.showinfo("Terms and Conditions", """
    Terms and Conditions:
    1. You will only use this tool on networks and systems for which you have explicit permission.
    2. You will not use this tool to violate any laws, regulations, or terms of service.
    3. You will not use this tool to harm, disrupt, or exploit any networks or systems.
    4. You will not use this tool to intercept, collect, or store any sensitive or confidential information.
    5. You will not redistribute or sell this tool without the express permission of the author.
    6. The author is not responsible for any damages or losses incurred as a result of using this tool.
    7. You will respect the privacy and security of all networks and systems you interact with using this tool.
    """)

if __name__ == "__main__":
    create_gui()

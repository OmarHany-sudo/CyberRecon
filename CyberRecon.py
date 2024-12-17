import os
import nmap
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# دالة مسح الأهداف باستخدام nmap
def scan_target(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-65535')  # زيادة نطاق المنافذ
    return scanner

# دالة توليد تقرير
def generate_report(scan_data, output_file):
    with open(output_file, 'w') as f:
        for host in scan_data.all_hosts():
            f.write(f"Host: {host} ({scan_data[host].hostname()})\n")
            f.write(f"State: {scan_data[host].state()}\n")
            for proto in scan_data[host].all_protocols():
                f.write(f"Protocol: {proto}\n")
                ports = scan_data[host][proto].keys()
                for port in ports:
                    f.write(f"Port: {port}\tState: {scan_data[host][proto][port]['state']}\n")
            f.write("\n")
    messagebox.showinfo("Success", f"Report saved to {output_file}")

# دالة بدء المسح
def start_scan():
    target = target_entry.get()
    if not target:
        messagebox.showwarning("Warning", "Please enter a target")
        return
    scan_data = scan_target(target)
    output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if output_file:
        generate_report(scan_data, output_file)

# إعداد واجهة Tkinter
root = tk.Tk()
root.title("Vulnerability Scanner")
root.geometry("500x300")
root.configure(bg="#f0f0f0")

# إطار العنوان
title_frame = tk.Frame(root, bg="#003366", height=50)
title_frame.pack(fill="x")
title_label = tk.Label(title_frame, text="Vulnerability Scanner", bg="#003366", fg="white", font=("Helvetica", 16))
title_label.pack(pady=10)

# إطار الإدخال
input_frame = tk.Frame(root, bg="#f0f0f0")
input_frame.pack(pady=20)
target_label = tk.Label(input_frame, text="Target IP or URL:", bg="#f0f0f0", font=("Helvetica", 12))
target_label.grid(row=0, column=0, padx=10, pady=10)
target_entry = tk.Entry(input_frame, width=40, font=("Helvetica", 12))
target_entry.grid(row=0, column=1, padx=10, pady=10)

# زر بدء المسح
scan_button = tk.Button(root, text="Start Scan", command=start_scan, bg="#003366", fg="white", font=("Helvetica", 12))
scan_button.pack(pady=10)

root.mainloop()

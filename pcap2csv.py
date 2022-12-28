#!/usr/bin/env python2

from tkinter import filedialog as fd
import pyshark # pcap reader / parser
from collections import defaultdict
import tkinter as tk
import sbp

def pcap2csv(INPUT_FILE_NAME, OUTPUT_FILE_NAME, PORT):
    try:
        if not INPUT_FILE_NAME or not PORT:
            return
        capture = pyshark.FileCapture(INPUT_FILE_NAME)

        count=defaultdict(int)
        f = open(OUTPUT_FILE_NAME, "w")

        for packet in capture:
            try:
                source_port = packet[packet.transport_layer].srcport
                if int(source_port) == PORT:
                    SBP_bin=bytearray.fromhex(packet.tcp.payload.replace(":",""))
                    if SBP_bin[0]!= 0x55:
                        f.write(str(packet.sniff_time)+ "Skipping ill-formed message :"+packet.tcp.payload+"\n")
                        continue
                    a=sbp.client.framer.SBP.unpack(SBP_bin)
                    count[a.msg_type]+=1
                    b=sbp.table.dispatch(a)
                    f.write(str(packet.sniff_time)+"Duro msg: sender="+str(a.sender)+"msg_type="+str(a.msg_type)+" ("+str(sbp.table._SBP_TABLE[int(a.msg_type)].__name__)+str(b)+"\n")
                    continue
            except AttributeError as e:
                pass
        f.close()
        setStatus("Parsed data written in : \n" + OUTPUT_FILE_NAME)
        for key, value in sorted(count.items(), key=lambda item: item[1], reverse=True):
            setStatus("Packet type " + key + "\n(" + sbp.table._SBP_TABLE[int(key)].__name__ + "): " + count[key] +" packets")
    except Exception:
        setStatus("Error when proccessing.")

def setStatus(text):
    statusLabel.config(text = "Status : \n" + text)

def openFile():
    selectedFile = fd.askopenfilename()
    if not selectedFile:
        return
    setStatus("File Selected : \n" + selectedFile)

    selectedFileName = selectedFile.split("/")[-1].split(".")[0]
    saveFile = fd.asksaveasfile(initialfile = selectedFileName + '.txt', defaultextension=".txt", filetypes=[("All Files","*.*"),("Text Documents","*.txt")]).name
    if not saveFile:
        return
    
    pcap2csv(selectedFile, saveFile, portTextBox.get())


window = tk.Tk()
window.geometry("300x250")
window.resizable(False, False)
window.title("pcap2csv")
# window.iconbitmap('./files./icon.ico')

startButton = tk.Button(window, text="Select File", bg="gray", fg="white", border="0", activebackground="#A9A9A9", command=openFile)
startButton.pack()
startButton.place(anchor="n", height=75, width=250, x=150, y=50)

statusLabel = tk.Label(window, text="Status : ")
statusLabel.pack()
statusLabel.place(anchor="n", x=150, y=135)

portLabel = tk.Label(window, text="Port : ")
portLabel.pack()
portLabel.place(anchor="n", x=105, y=200)

portTextBox = tk.Entry(window)
portTextBox.pack()
portTextBox.place(anchor="n", x=160, y=200, width=75, height=23)
portTextBox.insert(string="55555", index=tk.END)

# Start the GUI
window.mainloop()
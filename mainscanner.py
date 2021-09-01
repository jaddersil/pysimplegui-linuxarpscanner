from ipaddress import ip_address
from threading import Thread
from time import sleep

import PySimpleGUI as sg
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff, srp

ip_range = []  # IP list to scan
list_hosts_answers = []
list_duplicated_macs = []  # macs found, by ip.
_rangeA = "10.1.11.1"
_rangeB = "10.1.11.255"
wait_time = 120
scan_mode = 1


# store arp reponses
def packets(packet):
    if packet[ARP].op == 2:
        # add ip and mac in the brute list
        list_hosts_answers.append([packet[ARP].psrc, packet[ARP].hwsrc])  # add items set


# listen to the network and call prn=packets when it is an arp packet
def worker():
    sniff(prn=packets, filter="arp", iface=None, timeout=wait_time)  #  timeout=60


# >>> send packets to induce arp responses
def send_packets():
    print("Wait...")
    i = 100 / len(ip_range)
    var_barra = 0
    for ip_nr in ip_range:
        srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip_nr)), iface=None, timeout=0.01, verbose=False)
        #  sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip_nr)), inter=0, loop=0, iface=None, iface_hint=None, count=None, verbose=None, realtime=None, return_packets=False, socket=None)
        var_barra = var_barra + i
        window.Element('ProgBar').UpdateBar(var_barra)
        window.Element('Ip_Progbar').Update(ip_nr)


# ------ Core begin ------ #
def core_program():
    # iface_search = input("Enter the interface name for sniff (e.g. enp3s0, None): ")
    global _rangeA
    global _rangeB

    # build source of ips
    while ip_address(_rangeA) <= ip_address(_rangeB):
        ip_var = ip_address(_rangeA)
        ip_range.append(ip_var)
        _rangeA = ip_address(_rangeA) + 1

    t = Thread(target=worker)
    t.start()

    sleep(2)  # to do sniff wait...

    send_packets()

    if t.is_alive():
        print('Ending...')
        window.refresh()
        sleep(10)

    # print("Thread finished")
    print("")
    print("RESULTS: ")
    print("")

    list_hosts_answers.sort()  # to sort brute results list

    # to filter an show
    x_linha = ['0.0.0.0', '00:00:00:00:00:00']
    flag = 0  # if exist or do not exist changes
    for linha in list_hosts_answers:
        if (linha[0] == x_linha[0]) & (linha[1] != x_linha[1]):
            print(x_linha)
            print(linha)
            flag = 1
        x_linha[0] = linha[0]
        x_linha[1] = linha[1]

    if flag == 1:
        window.Element('Image').Update(r'.\img_attention.png')
    else:
        window.Element('Image').Update(r'.\img_ok.png')
        print('No bad!')

    # window.Element('Stop').Update(disabled=True)
    window.Element('Start').Update(disabled=False)
    # ------ Core End ------ #


# sg.ChangeLookAndFeel('GreenTan')

# ------ Menu Definition ------ #
menu_def = [['File', ['Exit']],
            ['Help', ['Help', 'About...']]]
# ------ Body ------ #
layout = [
    [sg.Menu(menu_def, tearoff=True)],
    [sg.Text('')],
    [sg.Text('Use this tool to find devices sharing the same IPv4 address on your subnet', font=('Helvetica', 12, 'bold'))],
    [sg.Text('')],
    [sg.Text('                                                  '), sg.Button('Start', tooltip='Click to run scan', size=(15, 1), key='Start')],
    [sg.Text('')],
    [sg.Text('_' * 80)],
    [sg.Text('Range', font=('Helvetica', 10, 'bold')), sg.Text('between:'), sg.InputText(default_text='10.1.11.1', size=(15, 3), key='Ip_First'), sg.Text(' and '), sg.InputText(default_text='10.1.11.255', size=(15, 3), key='Ip_Last')],
    [sg.Text('_' * 80)],
    [sg.Text('Scan Mode: ', font=('Helvetica', 10, 'bold')), sg.Radio('Single scan', group_id='RADIO1', default=True, size=(10, 1), key='SingleScan'), sg.Radio('Periodic scan', group_id='RADIO1', key='PeriodicScan', disabled=1), sg.Radio('Passive mode', group_id='RADIO1', key='PassiveMode', disabled=1)],
    [sg.Text('Time to listen: ', font=('Helvetica', 10, 'bold')), sg.InputText('60', size=(5, 3), key='ScanTime', disabled=0), sg.Text('secs')],
    [sg.Text('_' * 80)],
    [sg.Text('Inquiring hosts:', font=('Helvetica', 10, 'bold')), sg.ProgressBar(100, orientation='h', size=(20, 20), key='ProgBar'), sg.Text('', key='Ip_Progbar', size=(15, 1))],
    [sg.Text('_' * 80)],
    [sg.Text('Results:', font=('Helvetica', 10, 'bold'))],
    [sg.Text('                      '), sg.Output(size=(45, 15)), sg.Image(r'.\img_clear.png', key='Image')],
    [sg.Text('')],
    [sg.Text('')]
]


# sg.Image(r'.\img_ok.png', key='Image')
"""
    [
    sg.Frame(layout=[
        [sg.Text('Alarm sound:'), sg.Checkbox('', default=True, key='SoundCheck'), sg.Text('name_sound.mp3')],
        [sg.Text('Save results to file:'), sg.Checkbox('', key='FileCheck'), sg.Text('View old',)],
        [sg.Text('Save parameters for next scan:'), sg.Checkbox('', key='ParametersCheck')],
        ], title='Misc', title_color='red', relief=sg.RELIEF_SUNKEN, tooltip='Use these to set flags'),
    sg.Frame(layout=[
        [sg.Button('Start', tooltip='Click to run scan', size=(15,1), bind_return_key='Start')],
        [sg.Cancel("Stop", tooltip='Click to stop scan', size=(15,1), bind_return_key='Stop')]
        ], title=''),
    ],
"""


def helppage():

    sg.popup(
        """HELP

It is possible to search for duplicate IPs only in the subnet your computer is on.

Before starting a scan, define at least the following:

Range:
    Enter: enter the first and last IP of the range you want to scan. E.g.: 10.1.8.1 and 10.1.11.255

Scan Mode:
    Single scan: performs a scan and exits.
    Periodic Scan (not available): Performs a scan, waits an interval in minutes, and scans again.
    Passive mode (not available): Evaluates network packet traffic without provoking hosts.
            
Time to listen:
    Leave 60 or set to a suitable time for the amount of IPs in the defined range or IPs.
        """, title='Help', button_type=0)


def about():
    sg.popup(
        """        
        lan-scanner-simplegui
        
        2019@Lançanova
                
        Python, scapy, Tkinter, ipaddres, PySimpleGui
        
        PSF Licence Agreement for Python 3.7.4 
        (https://docs.python.org/3/license.html)
        

        """,
        title='About...', button_type=0)


# ------ Load window ------ #
window = sg.Window('Lan-scanner-simplegui', layout, default_element_size=(40, 1), grab_anywhere=False)
window.Finalize()
# window.Element('Stop').Update(disabled=True)
window.Element('Start').Update(disabled=False)
#window.Element('Image').Update(visible=False)
# window.Element('Image').Update(Visible=True)

# ------ Listen window ------ #
while True:  # Event Loop
    event, values = window.Read(timeout=10)

    if event is None or event == 'Exit':
        break
    if event == 'Start':
        window.Element('Start').Update(disabled=True)
        # window.Element('Stop').Update(disabled=False)
        # window.Element('MultResult').Update('')
        _rangeA = values['Ip_First']
        _rangeB = values['Ip_Last']
        wait_time = int(values['ScanTime'])
        if values['SingleScan']:
            scan_mode = 1
        if values['PeriodicScan']:
            scan_mode = 2
        if values['PassiveMode']:
            scan_mode = 3

        core_program()  #  call core

    elif event == 'Help':
        helppage()
    elif event == 'About...':
        about()

# done with loop... need to destroy the window as it's still open
window.Close()
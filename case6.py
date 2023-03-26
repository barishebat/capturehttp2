from scapy.layers import http
from scapy.all import *
import sys


def pcap_http (file):

    packets = rdpcap(file)
    data_bytes = 0
    new_data_bytes = 0
    http_main_url = ''
    total_http = 0
    for pkt in packets:
        if pkt.haslayer("HTTPRequest"):
            http_layer = pkt.getlayer("HTTPRequest")
            data_bytes = int(len(bytes(pkt)))
            #http_bytes = "{0[Data]}".format(http_layer.fields)
            new_data_bytes = new_data_bytes + data_bytes
            url = "{0[Host]}".format(http_layer.fields)
            url = url.replace("b'","")
            url = url.replace("'","")
            main_url= 'http://' f'{url} '
            #print(main_url)
            if main_url not in http_main_url:
                  http_main_url =http_main_url + main_url + ' || '
            #print(http_layer)
            total_http = total_http + 1


    print("HTTP GET REQUEST FLOWS :",int(total_http))
    print("HTTP DATA BYTES :", new_data_bytes)
    print("HTTP TOP HOSTNAMES ARE :",http_main_url[:-3])


def main(arguments):
    #print(arguments)
    if len(arguments) == 2:        
        pcap_http(arguments[1])


if __name__ == "__main__":
    main(sys.argv)

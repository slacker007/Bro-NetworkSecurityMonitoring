



#! /bin/bash
	                      #########################################################################
                        #                                                                       #
                        #                            \|/ 2015 \|/                               #
                        #               Custom Script That Monitors Given Anamolies             #
                        #               SSL, Files, DNS, & HTTP traffic on a given              #
                        #               Network using bro scripts.                              #
                        #                                                                       #
                        #                       Written by: @realslacker007                     #
                        #                                 : @killswitch-gui                     #
                        #                                                                       #
                        #########################################################################


BLUE='\033[0;34m';
RED='\033[0;31m';
GREEN='\033[0;32m';
PURPLE='\033[0;35m';
YELLOW='\033[1;33m';
NC='\033[0;0m';
CYAN='\033[0;36m';
GRAY='\033[0;37m';


bro -i eth1 extract-all.bro .new_connections.bro quick_httpscript.bro &

sleep 20;


while (( 1 !=0 ))
do

echo -e "${GRAY}******************************************************************************************************************************************${GRAY}";
echo -e "${CYAN}						LIVE FEED FROM NETWORK.  -20 SECONDS							  ${CYAN}";
echo -e "${GRAY}******************************************************************************************************************************************${GRAY}";
echo;
echo -e "${YELLOW}*******************************************************CURRENT CONNECTIONS****************************************************************${YELLOW}";
echo
cat $PWD/conn.log | bro-cut -d ts uid id.orig_h id.resp_h  service| sort -u > running_conns.txt;
cat running_conns.txt | tail -n 10;
sleep 1;
rm running_conns.txt;
echo;
echo -e "${PURPLE}************************************************CURRENT DNS REQUESTS/RESPONSES************************************************************${PURPLE}";
echo
cat $PWD/dns.log | bro-cut -d ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto query | sort -u > running_dns.csv;
cat running_dns.csv | tail -n 10;
sleep 1;
rm running_dns.csv
echo;
echo -e "${RED}*******************************************************CURRENT HTTP CONNECTIONS**************************************************************${RED}";
echo
cat $PWD/http.log | bro-cut -d ts id.orig_h id.orig_p id.resp_h id.resp_p host referrer | sort -u  > http_conns.txt;
cat http_conns.txt | tail -n 10;
sleep 1;
rm http_conns.txt;
echo;
echo -e "${NC}*******************************************************CURRENT HTTP URI'S ********************************************************************${NC}";
echo
cat $PWD/http.log | bro-cut -d ts method user_agent | sort -u > url_req.txt;
cat url_req.txt | tail -n 5;
sleep 1;
rm url_req.txt;
echo;
echo -e "${GREEN}*******************************************************CURRENT FILES TRANSMITTED************************************************************${GREEN}";
echo
cat $PWD/files.log | bro-cut -d ts fuid tx_hosts rx_hosts conn_uids source | sort -u > trf_files.txt;
cat trf_files.txt;
sleep 1;
rm trf_files.txt;
echo;

sleep 20;
clear;
done










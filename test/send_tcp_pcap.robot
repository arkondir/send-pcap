*** Settings ***
Library     ../modules/TcpClient.py      WITH NAME   TPC

*** Test Cases ***
1. Sending TCP flow from PCAP.
    [Documentation]    Send data from pcap to host:port.
    Start
    Send file    data/chain_cfu_B.pcap    localhost    8686

    


*** Keywords ***
Start
    TPC.start_client
Send file
    [Arguments]    ${FILE}    ${IP}    ${PORT}
    TPC.send_data    ${FILE}    ${IP}    ${PORT}

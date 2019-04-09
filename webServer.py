# Imports
import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_table_experiments as dt
from dash.dependencies import Input, Output, State
import pandas as pd
import plotly

# Processes libraries
from multiprocessing import Process
from multiprocessing.managers import BaseManager
import psutil
import subprocess
import signal

# Time libraries
import time

# Local libraries
from utils import *
from header import Header
from sniffer import Sniffer
import sniffer

# Pie chart
import plotly.plotly as py
import plotly.graph_objs as go

# Scapy library
from scapy.all import *



# Start apache2
subprocess.check_call("systemctl start apache2".split())
signal.signal(signal.SIGINT, signal_handler)

# INPUT FILES / READ DATA
# This file will be updated by 'scan.py', and read by the web server
INPUT_SCAN     = 'data/scan.csv'
SCAN_TABLE     = pd.read_csv(INPUT_SCAN, sep=',')

SUMM_MAP     = {}
SUMM_MAP_KEYS = SUMM_MAP.keys()
SUMM_MAP_VALS = SUMM_MAP.values()

# Define the Dashboard
app = dash.Dash(__name__)
app.config['suppress_callback_exceptions']=True

# Make it work without internet
app.css.config.serve_locally = True
app.scripts.config.serve_locally = True

# Manage processes
BaseManager.register('Sniffer', Sniffer)
manager = BaseManager()
manager.start()
snifferInst = manager.Sniffer("wlan0", "wlan0")













# Describe the layout, or the UI, of the app
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content'),

    # Bizarrement on a besoin de 'declarer' certains objets, sinon il y a
    # des bugs avec les callbacks.
    html.Div(dt.DataTable(rows=[{}]), style={'display': 'none'}),
])



# ************************* #
#         WEB PAGES LIST        #
# ************************* #
### WELCOME PAGE ###
page_welcome = html.Div([
    html.Div([
        Header(app),

        html.Div([
            html.Div([
                html.H6('What is a TAP ?', className="gs-header gs-table-header padded"),
                html.Br([]),
                html.P("\
                    A network tap is a hardware device which provides\
                    a way to access the data flowing across a computer\
                    network. In many cases, it is desirable for a third\
                    party to monitor the traffic between two points in\
                    the network. If the network between points A and B\
                    consists of a physical cable, a \"network tap\" may\
                    be the best way to accomplish this monitoring. The\
                    network tap has (at least) three ports: an A port,\
                    a B port, and a monitor port. A tap inserted between\
                    A and B passes all traffic (send and receive data\
                    streams) through unimpeded in real time, but also\
                    copies that same data to its monitor port, enabling\
                    a third party to listen.", style={'text-align': 'justify', 'padding':'2px'}),
                ], className="six columns"),
            html.Div([
                html.H6('What is the project ?', className="gs-header gs-table-header padded"),
                html.Br([]),
                html.P("\
                    Our goal with this project is to use a RaspberryPi\
                    to monitor network trafic through the TAP. The features\
                    proposed are either active, when they generate trafic,\
                    or passive, when they only read and analyse the trafic.\
                    Just like some Intrusion Detection System (IDS), the data\
                    analysis is represented on a web interface where users can\
                    see human readable informations and statistics. In addition\
                    if an attack is detected (e.g. a DoS attack), an alert will\
                    be raised and shown on the web interface.<br><br>\
                    This project is realised through the SSIR (Information\
                    Systems and Network Securiy) of the Paul Sabatier\
                    University, in Toulouse, France.", style={'text-align': 'justify', 'padding':'2px'}),
                ], className="six columns"),
            ], className="row"),
        ])
    ], className="page"),
#_________________________________________________________________________________________________#

### ERROR PAGE ###
page_error = html.Div([  # 404
    Header(app),

    html.P(["404 Page not found"])

    ], className="page"),
#_________________________________________________________________________________________________#

### SUMMARY PAGE ###
page_summ = html.Div(id='summary', children=[
    Header(app),

    # Title
    html.H4(children='Summary'),
    html.Button(id='snif_reset', type='submit', children='Reset'),
    html.Button(id='snif_start', type='submit', children='Start'),
    
    # Display Bandwidth squares
    html.Div([indicator("#00cc96", "Bandwidth Rx", "summary_bdwidth_rx"),
        indicator("#00cc96", "Bandwidth Tx", "summary_bdwidth_tx"),
        indicator("#00cc96", "Packet count", "summary_total_pkt")
        ], className='row'
    ),

    # Display graph
    html.Div(id='summary_div'),
    html.Div([update_protocol_graph([],[])], id='graph-protocols-div'),
    


        # DIAGRAMME EN CAMEMBERT
            # dcc.Graph(
         #        id = "graph-1",
         #        figure={
         #            'data': [
         #                go.Pie(
         #                    labels=SUMM_MAP_KEYS,
         #                    values=SUMM_MAP_VALS,
         #                ),
         #            ]}, 
            # style={'text-align': 'center'}),

        # Define autorefresh interval
        dcc.Interval(
            id='refresh-summary',
            interval=2*1000, # in milliseconds
            n_intervals=0)

        ], className="page"),
#_________________________________________________________________________________________________#

### SCAN PAGE ###
page_scan = html.Div(id='scan', children=[
    Header(app),

    # Title
    html.H4(children='Scan results'),
    html.P('IP Address must follow one of these formats:\n'),
    dcc.Input(id='ip', value='IP Adress', type='text'),
    html.Button(id='submit-button-scan', type='submit', children='Scan'),
    html.Div(id='output_div'),

    # Display table
    dt.DataTable(
        rows=SCAN_TABLE.to_dict('records'),

        # optional - sets the order of columns
        columns=sorted(SCAN_TABLE.columns),

        row_selectable=False,
        filterable=True,
        sortable=True,
        selected_row_indices=[],
        id='table-scan',
        editable=False
    ),

    # Define autorefresh interval
    dcc.Interval(
        id='refresh-scan',
        interval=5*1000, # in milliseconds
        n_intervals=0)

], className="page")
#_________________________________________________________________________________________________#

# CSS
external_css = ["https://cdnjs.cloudflare.com/ajax/libs/normalize/7.0.0/normalize.min.css",
                "https://cdnjs.cloudflare.com/ajax/libs/skeleton/2.0.4/skeleton.min.css",
                "//fonts.googleapis.com/css?family=Raleway:400,300,600",
                "https://codepen.io/bcd/pen/KQrXdb.css",
                "https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css"]

for css in external_css:
    app.css.append_css({"external_url": css})

external_js = ["https://code.jquery.com/jquery-3.2.1.min.js",
               "https://codepen.io/bcd/pen/YaXojL.js"]

for js in external_js:
    app.scripts.append_script({"external_url": js})







#####################################
#####################################
##            CALLBACKS            ##
#####################################
#####################################

######################
# HANDLE USER EVENTS #
######################
# LOAD PAGE
@app.callback(dash.dependencies.Output('page-content', 'children'),
              [dash.dependencies.Input('url', 'pathname')])
def display_page(pathname):
    if pathname == '/RaspberryPiReport' or pathname == '/RaspberryPiReport/scan':
        return page_scan
    elif pathname == '/summary' or pathname == '/RaspberryPiReport/summary':
        return page_summ
    elif pathname == '/welcome' or pathname == '/RaspberryPiReport/welcome':
        return page_welcome
    else:
        return page_welcome

# PARSE AND SCAN IP
@app.callback(Output('output_div', 'children'),
                  [Input('submit-button-scan', 'n_clicks')],
                  [State('ip', 'value')],
                  )
def update_scan(clicks, input_value):
    if clicks is not None:
        if not valid_ip(input_value):
            return 'This IP format is not valid: "{}"'.format(input_value)
        p = Process(target=scan, args=(input_value,))
        p.start()
        p.join()




#############################
# HANDLE AUTOREFRESH EVENTS #
#############################
# AUTOREFRESH SCAN
@app.callback(
    Output('table-scan', 'rows'),
    [Input('refresh-scan', 'n_intervals')])
def update_table(a):
    SCAN_TABLE = pd.read_csv(INPUT_SCAN)
    return SCAN_TABLE.to_dict('records')

# AUTOREFRESH SCAN | BANDWIDTH RECEIVING
@app.callback(
    Output('summary_bdwidth_rx', 'children'),
    [Input('refresh-summary', 'n_intervals')])
def update_summary_bandwidth_rx(a):
    rx1 = get_bytes('rx')
    time.sleep(1)
    rx2 = get_bytes('rx')
    rx_speed = round((rx2 - rx1)/1000000.0, 4)
    return_value = rx_speed*1000
    return str(return_value)

# AUTOREFRESH SCAN | BANDWIDTH EMISSION
@app.callback(
    Output('summary_bdwidth_tx', 'children'),
    [Input('refresh-summary', 'n_intervals')])
def update_summary_bandwidth_tx(a):
    tx1 = get_bytes('tx')
    time.sleep(1)
    tx2 = get_bytes('tx')
    tx_speed = round((tx2 - tx1)/1000000.0, 4)
    return_value = tx_speed*1000
    return str(return_value)

# AUTOREFRESH SCAN | BANDWIDTH EMISSION
@app.callback(
    Output('summary_total_pkt', 'children'),
    [Input('refresh-summary', 'n_intervals')])
def update_summary_pkt_count(a):
    return str(snifferInst.getPkt())

# AUTOREFRESH SCAN | PROTOCOLS GRAPH
@app.callback(
            Output('graph-protocols-div', 'children'),
            [Input('refresh-summary', 'n_intervals')])
def update_protocol_graph(a):
    SUMM_MAP_KEYS = snifferInst.getProtoKeys()
    SUMM_MAP_VALS = snifferInst.getProtoVals()
    return html.Div(
        [
            dcc.Graph(
            id = "graph-1",
            figure={
                'data': [
                    go.Bar(
                        x = SUMM_MAP_KEYS,
                        y = SUMM_MAP_VALS,
                        marker = {
                          "color": "rgb(191, 44, 12)",
                          "line": {
                            "color": "rgb(255, 255, 255)",
                            "width": 2
                          }
                        },
                    ),
                ]},

            # Montrer ou non les options permettant de modifier le graphe
            config={
                'displayModeBar': False
            })])




##########################
# HANDLE PROTOCOL  STATS #
##########################
# Start packet sniffing
@app.callback(Output('snif_start', 'children'),
            [Input('snif_start', 'n_clicks')])
def start_snif(clicks):
    if clicks is not None:
        if clicks % 2 == 1:
            snifferProc = Process(target=sniffer.runSniffer, args=[snifferInst])
            snifferProc.start()
            snifferInst.setPID(snifferProc.pid)
            return "Stop"
        else:
            print(snifferInst.getPID())
            p = psutil.Process(snifferInst.getPID())
            p.kill()
            return "Start"
    return "Start"

# End packet sniffing
@app.callback(Output('snif_reset', 'title'),
            [Input('snif_reset', 'n_clicks')])
def reset_snif(clicks):
    if clicks is not None:
        snifferInst.reset()
    return "Reset"







# Run the server
if __name__ == '__main__':
    app.run_server(debug=True)


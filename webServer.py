# Imports
import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_table_experiments as dt
#import dash_table
from dash.dependencies import Input, Output, State
import pandas as pd

# Processes libraries
from multiprocessing import Process
import time

# Local libraries
from utils import *

# Signal libraries
import signal

# test
from header import Header

# Start apache2
subprocess.check_call("systemctl start apache2".split())
signal.signal(signal.SIGINT, signal_handler)

# INPUT FILES / READ DATA
# This file will be updated by 'scan.py', and read by the web server
INPUT_SCAN = 'data/scan.csv'
DATA_TABLE = pd.read_csv(INPUT_SCAN, sep=',')

# Input for snort alerts
INPUT_SCAN_alerts = '/var/log/alert.csv'
DATA_TABLE_alerts = pd.read_csv(INPUT_SCAN_alerts, sep=',')

# Define the Dashboard
app = dash.Dash(__name__)
app.config['suppress_callback_exceptions']=True

# Make it work without internet
app.css.config.serve_locally = True
app.scripts.config.serve_locally = True

# Describe the layout, or the UI, of the app
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content'),
	html.Div(dt.DataTable(rows=[{}]), style={'display': 'none'})
])











# ************************* #
# 		WEB PAGES LIST		#
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
					a third party to listen.", style={'text-align': 'justify'}),
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
					University, in Toulouse, France.", style={'text-align': 'justify'}),
				], className="six columns"),
			], className="row"),
		])
	], className="page"),

### ERROR PAGE ###
page_error = html.Div([  # 404
	Header(app),

    html.P(["404 Page not found"])

    ], className="page"),

### ALERT PAGE ###
page_alerts = html.Div([
	Header(app),
    html.H4(children=' '),
    dt.DataTable(
        rows=DATA_TABLE_alerts.to_dict('record'),
        columns=DATA_TABLE_alerts.columns,
        row_selectable=False,
        filterable=True,
        sortable=True,
        selected_row_indices=[],
        id='tablee',
        editable=False
    ),

# Define autorefresh interval
    dcc.Interval(
        id='interval-componentt',
        interval=5*1000, # in milliseconds
        n_intervals=0)
    ], className="page"),


### SCAN PAGE ###
page_scan = html.Div(id='scan', children=[
    Header(app),

    # Title
    html.H4(children='Scan results'),
    html.P('IP Address must follow one of these formats:\n'),
    dcc.Input(id='username', value='IP Adress', type='text'),
    html.Button(id='submit-button', type='submit', children='Scan'),
    html.Div(id='output_div'),

    dt.DataTable(
        rows=DATA_TABLE.to_dict('records'),

        # optional - sets the order of columns
        columns=sorted(DATA_TABLE.columns),

        row_selectable=False,
        filterable=True,
        sortable=True,
        selected_row_indices=[],
        id='table',
        editable=False
    ),

    # Define autorefresh interval
    dcc.Interval(
        id='interval-component',
        interval=5*1000, # in milliseconds
        n_intervals=0)

], className="page")


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








###################################
# 			CALLBACKS 			  #
###################################
# LOAD PAGE
@app.callback(dash.dependencies.Output('page-content', 'children'),
              [dash.dependencies.Input('url', 'pathname')])
def display_page(pathname):
    if pathname == '/RaspberryPiReport' or pathname == '/RaspberryPiReport/scan':
        return page_scan
    elif pathname == '/welcome' or pathname == '/RaspberryPiReport/welcome':
    	return page_welcome
    elif pathname == '/alerts' or pathname == '/RaspberryPiReport/alerts':
    	return page_alerts
    else:
		return page_error


# PARSE AND SCAN IP
@app.callback(Output('output_div', 'children'),
                  [Input('submit-button', 'n_clicks')],
                  [State('username', 'value')],
                  )
def update_output(clicks, input_value):
    if clicks is not None:
        if not valid_ip(input_value):
	    return 'This IP format is not valid: "{}"'.format(input_value)
        p = Process(target=scan, args=(input_value,))
        p.start()
        p.join()


# HANDLE AUTOREFRESH EVENTS
@app.callback(
    Output('table', 'rows'),
    [Input('interval-component', 'n_intervals')])
def update_table(a):
    DATA_TABLE = pd.read_csv(INPUT_SCAN)
    return DATA_TABLE.to_dict('records')

@app.callback(
    Output('tablee', 'rows'),
    [Input('interval-componentt', 'n_intervals')])
def update_tablee(a):
    DATA_TABLE_alerts = pd.read_csv(INPUT_SCAN_alerts)
    return DATA_TABLE_alerts.to_dict('records')

# Run the server
if __name__ == '__main__':
    subprocess.Popen(["snort", "-dev", "-l", "/home/pi/SNORT_LOG_FILE","-c", "/home/pi/SNORT/snort-2.9.12/etc/snort.conf", "-i", "eth0"])
    app.run_server(debug=True)


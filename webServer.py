# Imports
import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_table_experiments as dt
from dash.dependencies import Input, Output, State
import pandas as pd


# INPUT FILES / READ DATA
# This file will be updated by 'scan.py', and read by the web server
INPUT_SCAN = 'data/scan.csv'
DATA_TABLE = pd.read_csv(INPUT_SCAN, sep=',')

# Define the Dashboard
external_stylesheets = ['sheet.css']
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

# Make it work without internet
app.css.config.serve_locally = True
app.scripts.config.serve_locally = True

# Define the content of the dashboard
app.layout = html.Div(children=[
    # Title
    html.H4(children='Scan results'),
    dcc.Input(id='username', value='Initial value', type='text'),
    html.Button(id='submit-button', type='submit', children='Submit'),
    html.Div(id='output_div'),
    # Define table
    dt.DataTable(
        rows=DATA_TABLE.to_dict('records'),

        # optional - sets the order of columns
        columns=sorted(DATA_TABLE.columns),

        row_selectable=False,
        filterable=True,
        sortable=True,
        selected_row_indices=[],
        id='table'
    ),

    # Define autorefresh interval
    dcc.Interval(
        id='interval-component',
        interval=5*1000, # in milliseconds
        n_intervals=0)
])

# Traitement de l'input de l'utilisateur
@app.callback(Output('output_div', 'children'),
                  [Input('submit-button', 'n_clicks')],
                  [State('username', 'value')],
                  )
def update_output(clicks, input_value):
    if clicks is not None:
        print(clicks, input_value)

# Treatment when autorefresh event occurs, here we read INPUT_SCAN and update table
@app.callback(
    Output('table', 'rows'),
    [Input('interval-component', 'n_intervals')])
def update_table(a):
    DATA_TABLE = pd.read_csv(INPUT_SCAN)
    return DATA_TABLE.to_dict('records')


# Run the server
if __name__ == '__main__':
    app.run_server(debug=True)

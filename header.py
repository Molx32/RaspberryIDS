import dash_html_components as html
import dash_core_components as dcc
import os

def Header(app):
    return html.Div([
        get_logo(app),
        get_header(),
        html.Br([]),
        get_menu()
    ])

def get_logo(app):
    logo = html.Div([
    html.Div([        
        html.Div(html.Img(src=app.get_asset_url('ut3_logo.png'), height='113', width='340')),
    ], className="ten columns padded"),
    ], className="row gs-header")
    return logo


def get_header():
    header = html.Div([

        html.Div([
            html.H5(
                'RaspberryPi TAP Project')
        ], className="twelve columns padded")

    ], className="row gs-header gs-text-header")
    return header


def get_menu():
    menu = html.Div([

        dcc.Link('Welcome   ', href='/RaspberryPiReport/welcome', className="tab first"),

        dcc.Link('Summary   ', href='/RaspberryPiReport/summary', className="tab"),

        dcc.Link('Scan   ', href='/RaspberryPiReport/scan', className="tab")

    ], className="row ")
    return menu
# -*- coding: utf-8 -*-

from bottle import Bottle, static_file, run

app = Bottle()

@app.route('/media')
def media():
  return static_file('getusermedia.html', root='./')

@app.route('/peer')
def peer():
  return static_file('rtcpeerconnection.html', root='./')

@app.route('/vendor/<filepath:path>')
def serve_static(filepath):
  return static_file(filepath, root='./vendor')

run(app, host='192.168.1.100', port=60080)

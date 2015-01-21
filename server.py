# -*- coding: utf-8 -*-

from bottle import Bottle, static_file, run

app = Bottle()

@app.route('/lab/datachannel')
def datachannel():
  return static_file('rtcdatachannel.html', root='./')

@app.route('/lab/videochat')
def videochat():
  return static_file('rtcpeerconnection.html', root='./')

@app.route('/lab/vendor/<filepath:path>')
def serve_static(filepath):
  return static_file(filepath, root='./vendor')

run(app, host='localhost', port=60081)

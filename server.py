# -*- coding: utf-8 -*-

from bottle import Bottle, static_file, run

app = Bottle()

@app.route('/lab/videochat')
def peer():
  return static_file('rtcpeerconnection.html', root='./')

@app.route('/lab/vendor/<filepath:path>')
def serve_static(filepath):
  return static_file(filepath, root='./vendor')

run(app, host='localhost', port=60081)

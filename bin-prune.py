import os,datetime,shutil

clean=False
os.chdir('bin/')

def clear():
  global clean

  a={}
  for it in next(os.walk('.'))[1]:
    d=it.split('__')[0]
    d=d.split('_')
    d[0]=tuple([int(i) for i in d[0].split('-')])
    d[1]=tuple([int(i) for i in d[1].split('-')])
    d=datetime.datetime( *(d[0]+d[1]) )
    #print(d)
    a[it] = int(d.timestamp())

  old = None
  if len(a.keys()) < 5:
    if clean:
      raise SystemExit(0)
    else:
      print('not allowed to prune directories less than 5')
      raise SystemExit(1)

  for n,t in a.items():
    if old is None:
      old = (n,t)
      continue

    if t < old[1]:
      old = (n,t)

  clean = True
  print("Delete much old directory: ", old)
  shutil.rmtree(old[0])

while True:
  clear()

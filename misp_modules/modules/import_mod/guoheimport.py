# -*- coding: utf-8 -*-

import datetime
import importlib
import json
import os
import sys
from pymisp import MISPEvent, MISPObject
# import  as ET
mispattributes = {'inputSource': ['file'], 'output': ['MISP objects'],
				'format': 'misp_standard'}

anhengobject = {'response':[{}]}


moduleinfo = {'version': 1, 'author': 'Christian Studer',
				'description': 'Import from GoAML',
				'module-type': ['import']}

def version():
	moduleinfo['config'] = moduleconfig
	return moduleinfo

'''
class AnHengParser():
	def __init__(self):
		self.misp_event = MISPEvent()

	def read_json(self, data):
		self.json = json.loads(date)
		# AnHeng = json.loads(date)
		# self.json = AnHeng["hits"]["hits"]
#		self.tree = ET.fromstring(data)

	def parse_xml(self):
		self.first_itteration()
		for t in self.tree.findall('transaction'):
			self.itterate(t, 'transaction')

	def first_itteration(self):
		# submission_date = self.tree.find('submission_date').text.split('+')[0]
		# self.misp_event.timestamp = int(time.mktime(time.strptime(submission_date, "%Y-%m-%dT%H:%M:%S")))
		for node in self.json['hits']['hits']:
			# element = self.tree.find(node)
			hits = node
			print(hits)

			if hits is not None:
				self.itterate(hits, element.tag)
'''
    # def itterate(self, tree, aml_type, referencing_uuid=None, relationship_type=None):
    #     objects = goAMLobjects[aml_type]
    #     referenced_uuid = referencing_uuid
    #     rel = relationship_type
    #     if aml_type not in nodes_to_ignore:
    #         try:
    #             mapping = goAMLmapping[aml_type]
    #             misp_object = MISPObject(name=mapping['misp_name'])
    #             for leaf in objects['leaves']:
    #                 element = tree.find(leaf)
    #                 if element is not None:
    #                     object_relation = mapping[element.tag]
    #                     attribute = {'object_relation': object_relation, 'value': element.text}
    #                     misp_object.add_attribute(**attribute)
    #             if aml_type == 'transaction':
    #                 for node in objects['nodes']:
    #                     element = tree.find(node)
    #                     if element is not None:
    #                         self.fill_transaction(element, element.tag, misp_object)
    #             self.misp_event.add_object(misp_object)
    #             last_object = self.misp_event.objects[-1]
    #             referenced_uuid = last_object.uuid
    #             if referencing_uuid and relationship_type:
    #                 referencing_object = self.misp_event.get_object_by_uuid(referencing_uuid)
    #                 referencing_object.add_reference(referenced_uuid, rel, None, **last_object)
    #         except KeyError:
    #             pass
    #     for node in objects['nodes']:
    #         element = tree.find(node)
    #         if element is not None:
    #             tag = element.tag
    #             if tag in relationship_to_keep:
    #                 rel = tag[2:] if tag.startswith('t_') else tag
    #             self.itterate(element, element.tag, referencing_uuid=referenced_uuid, relationship_type=rel)

    # @staticmethod
    # def fill_transaction(element, tag, misp_object):
    #     if 't_from' in tag:
    #         from_funds = element.find('from_funds_code').text
    #         from_funds_attribute = {'object_relation': 'from-funds-code', 'value': from_funds}
    #         misp_object.add_attribute(**from_funds_attribute)
    #         from_country = element.find('from_country').text
    #         from_country_attribute = {'object_relation': 'from-country', 'value': from_country}
    #         misp_object.add_attribute(**from_country_attribute)
    #     if 't_to' in tag:
    #         to_funds = element.find('to_funds_code').text
    #         to_funds_attribute = {'object_relation': 'to-funds-code', 'value': to_funds}
    #         misp_object.add_attribute(**to_funds_attribute)
    #         to_country = element.find('to_country').text
    #         to_country_attribute = {'object_relation': 'to-country', 'value': to_country}
    #         misp_object.add_attribute(**to_country_attribute)



# def version():
	# IP = '192.168.231.60:'
	# Port = '29201'
	# Index = 'tip.combination.ioc.intelligence.index'
	# Document = 'intelligence'
	# undetermined = '_search'
	# StorageAddress = '/home/misp/'
	# today = today=datetime.date.today() 
	# tomorrow = today + datetime.timedelta(days=1)
	# yesterday = today - datetime.timedelta(days=1)
	# b_slash="/"
	# condition = '\'{"size":10,"query":{"range":{"firstImportDate":{"gt":"\''+str(yesterday)+'\'","lt":"\''+str(tomorrow)+'\'"}}}}\''
	# InformationSources = "安恒"
	# OriginalData = "原数据"
	# ODateStorageAddress = StorageAddress + InformationSources + OriginalData + str(today) + ".json"
	# FormatStorageAddress = StorageAddress + InformationSources + str(today)+ ".json"
	# s = "curl \'" + IP + Port + b_slash + Index + b_slash + undetermined + "\' -d " + condition + " > " + ODateStorageAddress
	# print(s)
	# return s,ODateStorageAddress

# def download(s):
	# os.system(s)
def handler(q=False):
	misp = MISPEvent()
	if q is False:
		return False
	request = json.loads(q)
	dict2=request['hits']['hits']
	for i in dict2:
		Attribute=[]
		Object=[]
		Att0 = {"category":"External analysis","to_ids":True,"type":""}
		dict0 = dict
		dict0 = i
		_score = dict0["_score"]
		_type = dict0["_type"]
		_source = dict0["_source"]
		iocTags = _source["iocTags"]
		if iocTags["subjectType"]=="ip":
			Att0["type"]="ip-dst"
		elif iocTags["subjectType"]=="domain":
			Att0["type"]="domain"

		Tag = []
		dict1={"name":"安恒情报"}
		Tag.append(dict1)
		dict1 = {}
		dict1["name"] = iocTags["score"]["confidenceLevel"]
		Tag.append(dict1)
		try:
			dict1={}
			dict1["name"]=iocTags["score"]["riskLevel"]
			Tag.append(dict1)
		except:
			dict1={}
			dict1["name"]=""
			Tag.append(dict1)
		misp["Tag"]=Tag
		Att0["comment"]=""
		Att0["first_seen"]=iocTags["firstSeenTime"]
		Att0["last_seen"]=iocTags["lastSeenTime"]
		Att0["value"]=iocTags["subject"]
		Att0["Tag"]=[]
		Tag="Tag:" + str(iocTags["tags"][0]["mclass"])+":"+str(iocTags["tags"][0]["origin"])
		dict3=dict
		dict3={"name":Tag}
		Att0["Tag"].append(dict3)
		try:
			Family ="Familys:" +str( _source["familys"][0]["mclass"])+":"+str(_source["familys"][0]["origin"])
			dict3=dict
			dict3={"name":Family}
			Att0["Tag"].append(dict3)
		except IndexError:
			A={"name":""}
			Att0["Tag"].append(A)
		Attribute.append(Att0)
		Att1 = {"category":"Payload delivery","type":"sha256","to_ids":True}
		Att1["comment"]=""
		malware = _source["malware"]
		try:
			Att1["first_seen"]=malware[0]["firstSeenTime"]
			Att1["last_seen"]=malware[0]["lastSeenTime"]
			Att1["value"] = malware[0]["hash"]
			Att1["Tag"]=[]
			Tag1={"name":"subjec:" + str(malware["malware"][0]["subject"])}
			Att1["Tag"].append(Tag1)
			Tag1={"name":"origin:"+str(malware["malware"][0]["origin"])}
			Att1["Tag"].append(Tag1)
		except:
			Att1["first_seen"]=""
			Att1["last_seen"]=""
			Att1["value"] = ""
			Att1["Tag"]=[]
			Tag1={"name":""}
			Att1["Tag"].append(Tag1)
			Tah1={"name":""}
			Att1["Tag"].append(Tag1)
		Attribute.append(Att1)
		Att2={"type":"url","category":"External analysis","to_ids":False,"comment":"reference"}
		try:
			reference=_source["reference"]
			Att2["first_seen"]=reference[0]["firstSeenTime"]
			Att2["last_seen"]=reference[0]["lastSeenTime"]
			Att2["value"] = reference[0]["pageurl"]
			Att2["Tag"]=[]
			Tag2={"name":"subjec:"+str(reference[0]["subject"])}
			Att2["Tag"].append(Tag2)
			Tag2={"name":"origin:"+str(reference[0]["origin"])}
			Att2["Tag"].append(Tag2)
		except:
			Att2["first_seen"]=""
			Att2["last_seen"]=""
			Att2["value"] = ""
			Att2["Tag"]=[]
			Tag2={"name":""}
			Att2["Tag"].append(Tag2)
			Tag2={"name":""}
			Att2["Tag"].append(Tag2)
		Attribute.append(Att2)
		Att3={"category":"External analysis","comment":"trojan"}
		try:
			trojan = _source["trojan"]
			Att3["first_seen"]=trojan[0]["firstSeenTime"]
			Att3["last_seen"]=trojan[0]["lastSeenTime"]
			Att3["value"] = trojan[0]["url"]
			Att3["Tag"]=[]

			Tag3={"name":"subjec:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"origin:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"county:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"province:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"city:"}
			Att3["Tag"].append(Tag3)
		except:
			trojan = _source["trojan"]
			Att3["first_seen"]=""
			Att3["last_seen"]=""
			Att3["value"] = ""
			Att3["Tag"]=[]

			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"city":""}
			Att3["Tag"].append(Tag3)
		Attribute.append(Att3)
		misp["Attribute"]=Attribute

		Obj0={"name":"geolocation","template_uuid":"fdd30d5f-6752-45ed-bef2-25e8ce4d8a3"}

		try:
			geo=iocTags["geo"]
			OAtt=[]

			dict1={}
			dict1["object_relation"]="latitude"
			dict1["value"]=geo["latitude"]
			OAtt.append(dict1)
	
			dict1={}
			dict1["object_relation"]="longitude"
			dict1["value"]=geo["longitude"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="text"
			dict1["value"]=geo["geoPoint"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="city"
			dict1["value"]=geo["province"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="country"
			dict1["value"]=geo["countryName"]
			OAtt.append(dict1)
		except:
			dict1={}
			OAtt=[]
			dict1["object_relation"]="latitude"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="longitude"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="text"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="city"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="country"
			dict1["value"]=""
			OAtt.append(dict1)	

		Obj0["Attribute"]=OAtt
		Object.append(Obj0)	

		Obj1={"name":"passive-dns","meta-category":"network","template_uuid":"b77b7b1c-66ab-4a41-8da4-83810f6d2d6c"}
		passiveDns = _source["passiveDns"]
		try:
			Obj1["last_seen"]=passiveDns[0]["lastUpdateTime"]
			OAtt=[]
			dict1={}
			dict1["object_relation"]="rrname"
			dict1["value"]=passiveDns[0]["hostname"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rrtype"
			dict1["value"]=passiveDns[0]["recoedType"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rdata"
			dict1["value"]=passiveDns[0]["address"]
			OAtt.append(dict1)
		except:
			Obj1["last_seen"]=""
			OAtt=[]
			dict1={}
			dict1["object_relation"]="rrname"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rrtype"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rdata"
			dict1["value"]=""
			OAtt.append(dict1)	

		Obj1["Attribute"]=OAtt
		Object.append(Obj1)

		misp["Object"]=Object
		misp["info"]="安恒情报"
		misp["publish"]=True
		# res={"Event":Event}
	
		# response.append(res)
	print(misp.to_dict())
	# for key in misp:
	# 	print(key)
	# print(misp)
	return(misp)








	misp = MISPEvent()
	print(json.loads(misp.to_json()))

	misp['info']='安恒情报'
	misp['publish']=True
	# misp.publish
	# print(misp['uuid'])
	# print(misp.get_object_by_uuid(misp['uuid']))

	Att0 = {"category":"External analysis","to_ids":True,"type":""}
	misp['Attribute']=Att0







	print(misp.values)
	# print(misp['publish'])
	# print(q)

	r = {'response': [{'Event': misp}]}
	return r

# def handler(ODateStorageAddress):
	# dict2=[]
	# with open(ODateStorageAddress,"r")as f:
	# 	json_dict = json.loads(f.read())
	# 	dict2 = json_dict["hits"]["hits"]
	# 	f.close()
	# return dict2

def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup
'''
def introspection(dict2):
	response=[]
	for i in dict2:
		Event={}
		Attribute=[]
		Object=[]
		Att0 = {"category":"External analysis","to_ids":"TRUE","type":""}
		dict0 = dict
		dict0 = i
		_score = dict0["_score"]
		_type = dict0["_type"]
		_source = dict0["_source"]
		iocTags = _source["iocTags"]
		if iocTags["subjectType"]=="ip":
			Att0["type"]="ip-dst"
		elif iocTags["subjectType"]=="domain":
			Att0["type"]="domain"

		Tag = []
		dict1={"name":"安恒情报"}
		Tag.append(dict1)
		dict1 = {}
		dict1["name"] = iocTags["score"]["confidenceLevel"]
		Tag.append(dict1)
		try:
			dict1={}
			dict1["name"]=iocTags["score"]["riskLevel"]
			Tag.append(dict1)
		except:
			dict1={}
			dict1["name"]=""
			Tag.append(dict1)
		Event["Tag"]=Tag
		Att0["comment"]=""
		Att0["first_seen"]=iocTags["firstSeenTime"]
		Att0["last_seen"]=iocTags["lastSeenTime"]
		Att0["value"]=iocTags["subject"]
		Att0["Tag"]=[]
		Tag="Tag:" + str(iocTags["tags"][0]["mclass"])+":"+str(iocTags["tags"][0]["origin"])
		dict3=dict
		dict3={"name":Tag}
		Att0["Tag"].append(dict3)
		try:
			Family ="Familys:" +str( _source["familys"][0]["mclass"])+":"+str(_source["familys"][0]["origin"])
			dict3=dict
			dict3={"name":Family}
			Att0["Tag"].append(dict3)
		except IndexError:
			A={"name":""}
			Att0["Tag"].append(A)
		Attribute.append(Att0)
		Att1 = {"category":"Payload delivery","type":"sha256","to_ids":True}
		Att1["comment"]=""
		malware = _source["malware"]
		try:
			Att1["first_seen"]=malware[0]["firstSeenTime"]
			Att1["last_seen"]=malware[0]["lastSeenTime"]
			Att1["value"] = malware[0]["hash"]
			Att1["Tag"]=[]
			Tag1={"name":"subjec:" + str(malware["malware"][0]["subject"])}
			Att1["Tag"].append(Tag1)
			Tag1={"name":"origin:"+str(malware["malware"][0]["origin"])}
			Att1["Tag"].append(Tag1)
		except:
			Att1["first_seen"]=""
			Att1["last_seen"]=""
			Att1["value"] = ""
			Att1["Tag"]=[]
			Tag1={"name":""}
			Att1["Tag"].append(Tag1)
			Tah1={"name":""}
			Att1["Tag"].append(Tag1)
		Attribute.append(Att1)
		Att2={"type":"url","category":"External analysis","to_ids":False,"comment":"reference"}
		try:
			reference=_source["reference"]
			Att2["first_seen"]=reference[0]["firstSeenTime"]
			Att2["last_seen"]=reference[0]["lastSeenTime"]
			Att2["value"] = reference[0]["pageurl"]
			Att2["Tag"]=[]
			Tag2={"name":"subjec:"+str(reference[0]["subject"])}
			Att2["Tag"].append(Tag2)
			Tag2={"name":"origin:"+str(reference[0]["origin"])}
			Att2["Tag"].append(Tag2)
		except:
			Att2["first_seen"]=""
			Att2["last_seen"]=""
			Att2["value"] = ""
			Att2["Tag"]=[]
			Tag2={"name":""}
			Att2["Tag"].append(Tag2)
			Tag2={"name":""}
			Att2["Tag"].append(Tag2)
		Attribute.append(Att2)
		Att3={"category":"External analysis","comment":"trojan"}
		try:
			trojan = _source["trojan"]
			Att3["first_seen"]=trojan[0]["firstSeenTime"]
			Att3["last_seen"]=trojan[0]["lastSeenTime"]
			Att3["value"] = trojan[0]["url"]
			Att3["Tag"]=[]

			Tag3={"name":"subjec:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"origin:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"county:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"province:"}
			Att3["Tag"].append(Tag3)
			Tag3={"name":"city:"}
			Att3["Tag"].append(Tag3)
		except:
			trojan = _source["trojan"]
			Att3["first_seen"]=""
			Att3["last_seen"]=""
			Att3["value"] = ""
			Att3["Tag"]=[]

			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"name":""}
			Att3["Tag"].append(Tag3)
			Tag3={"city":""}
			Att3["Tag"].append(Tag3)
		Attribute.append(Att3)
		Event["Attribute"]=Attribute

		Obj0={"name":"geolocation","template_uuid":"fdd30d5f-6752-45ed-bef2-25e8ce4d8a3"}

		try:
			geo=iocTags["geo"]
			OAtt=[]

			dict1={}
			dict1["object_relation"]="latitude"
			dict1["value"]=geo["latitude"]
			OAtt.append(dict1)
	
			dict1={}
			dict1["object_relation"]="longitude"
			dict1["value"]=geo["longitude"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="text"
			dict1["value"]=geo["geoPoint"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="city"
			dict1["value"]=geo["province"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="country"
			dict1["value"]=geo["countryName"]
			OAtt.append(dict1)
		except:
			dict1={}
			OAtt=[]
			dict1["object_relation"]="latitude"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="longitude"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="text"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="city"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="country"
			dict1["value"]=""
			OAtt.append(dict1)	

		Obj0["Attribute"]=OAtt
		Object.append(Obj0)	

		Obj1={"name":"passive-dns","meta-category":"network","template_uuid":"b77b7b1c-66ab-4a41-8da4-83810f6d2d6c"}
		passiveDns = _source["passiveDns"]
		try:
			Obj1["last_seen"]=passiveDns[0]["lastUpdateTime"]
			OAtt=[]
			dict1={}
			dict1["object_relation"]="rrname"
			dict1["value"]=passiveDns[0]["hostname"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rrtype"
			dict1["value"]=passiveDns[0]["recoedType"]
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rdata"
			dict1["value"]=passiveDns[0]["address"]
			OAtt.append(dict1)
		except:
			Obj1["last_seen"]=""
			OAtt=[]
			dict1={}
			dict1["object_relation"]="rrname"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rrtype"
			dict1["value"]=""
			OAtt.append(dict1)

			dict1={}
			dict1["object_relation"]="rdata"
			dict1["value"]=""
			OAtt.append(dict1)	

		Obj1["Attribute"]=OAtt
		Object.append(Obj1)

		Event["Object"]=Object
		Event["info"]="安恒情报"
		Event["publish"]=True
		res={"Event":Event}
	
		response.append(res)

	misp = {"response":response}
	print(misp)
	return(misp)
'''
# def main():
	# config,ODateStorageAddress = version()
	# download(config)
	# introspection(handler(ODateStorageAddress))
	# x=[]
	# with open('test.json','r')as f:
	# 	x = json.loads(f.read())
	# print(type(x))
	# print(x)
	# misp = MISPObject()
	# misp[0]["publish"]="sssssssssss"
	# print(misp)
	# x = open('test.json', 'r').read()
	# print(x)
	# r = handler(q=x)
	# print(r)
	# handler('test.json')
	# x=open('test.json','r')
	# print(handler(x.read()))
	# with open('testtest.json','a')as f:
	# 	f.write(handler(x.read()))




# if __name__ == '__main__':
# 	main()

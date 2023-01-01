import requests
import pprint
import json
import base64
import time

MY_ID = ''
MY_TOKEN = ""

# search github iterator fuction *******************

def search_github(session, url):
    # session = requests.Session()
    # session.auth = (user, token)

    first_page = session.get(url)
    yield first_page

    next_page = first_page
    while next_page.links.get('next', None) is not None:
        next_page_url = next_page.links['next']['url']
        next_page = session.get(next_page_url)
        yield next_page

# search github iterator fuction *****************


checkit = (
    ("Eval function", "eval%28", "Potentially dangerous", "eval(", ""),
    ("SQL query", "SELECT", "Potentially dangerous", "f'select", ""),
    ("Uses Picle", "pickle","Potentially dangerous", "import pickle", ""),
    ("Open password", "password", "Has vulnerability", "password =", "")
)


# Авторизация
session = requests.Session()
session.auth = (MY_ID, MY_TOKEN)
main_url = "https://api.github.com/search/code?"

#--------------------------------------------------------------
# check all issues from checkit list
for chkit in checkit:
#

    out_items = {}
    code_type = chkit[0]
    status = chkit[2]  # Тип небезопасного кода
    search_str = chkit[3]
    add_url = "q=" + chkit[1] + "+in:file+language:python+extensions:py&per_page=100"
    request_url = main_url+add_url
    print(request_url)

    out_items["known vulnerability"] = code_type
    out_items["unsafe codes"] = []

# Iterate through pages
    for page in search_github(session, request_url):
        print(page.headers)
        pprint.pprint(page.headers)

        result = page.json()
        pprint.pprint(result)
        items = result['items']
        limit = 0

        for item in items:
            if not item['path'].startswith('venv'):
                #limit +=1
                # f*cking GitHub require to wait)
                time.sleep(3)  # Сон в 3 секунд
                repo = item["repository"]
                repo_url = repo["html_url"]
                print(repo_url)
                print(item["git_url"])
                file_response = session.get(item["git_url"])
                #print("****0********************************************************************************************")
                #pprint.pprint(file_response.json())
                file_bytes = base64.b64decode(file_response.json()['content'])
                try:
                    file_str = file_bytes.decode('utf-8')
                except:
                    break

                #print(file_str)
                #print("****1********************************************************************************************")
                pprint.pprint(file_bytes)
                data_list =[file_str]
                #print("****2********************************************************************************************")
                data_list = ''.join(data_list).split('\n')
                #print("****3********************************************************************************************")
                # check if string contains dangerous signature
                found = False
                for i in data_list:
                    if search_str in i:
                        i = i.lower()
                        #check if search_str is not a part of another sentence
                        pos = i.find(search_str)
                        if pos > 0 and i[pos-1].replace('_', '0').isalnum() or pos < 0:
                            found = False
                        else:
                            found = True
                        #print("**********************************************", "#check if search_str is not a part of another sentence", found)
                        #check if it's not commented
                        if found and i.find("#", 0, pos) >= 0:  #one line comment
                            found = False
                       # print("**********************************************","#one line comment", found)
                        cnt = 0
                        if found:
                            for j in data_list:
                                if i==j: break
                                if i.find("\"\"\"") >= 0:  #multi-line comment
                                    cnt+=1
                            if (cnt % 2) > 0:
                                found = False
                            #print("**********************************************", "#multi-line comment", found)
                        if found:
                            print(i)
                            break

                if found:
                    #print("**********************************************", "add data!!!!")
                    code_data = {}
                    code_data["repo"] = repo_url
                    code_data["module"] = item["name"]
                    code_data["url"] = item["html_url"]
                    code_data["status"] = status
                    out_items["unsafe codes"].append(code_data)
                #print("****4********************************************************************************************")
                # f*cking GitHub require to wait)
                time.sleep(3)  # Сон в 2 секунд
                limit+=1
                if limit > 10:
                    break
        # check all pages

    pprint.pprint(out_items)
    with open('data.txt', 'a') as outfile:
        json.dump(out_items, outfile, indent=4)

    #f*cking GitHub require to wait)
    time.sleep(10) # Сон в 100 секунд


import re

file = open("/home/wotu/C-DHCP/scripts/bib.txt", "r")
content = file.read()
splitted_content = content.split("@article")

for record in splitted_content[1:]:
    splitted_record = record.split(",")
    reference = splitted_record[0].replace("{", "")
    for element in splitted_record:
        if "title" in element:
            title_start = "title    =  \""
            title_end = url_start = " \\url{"
            url_end = "}\""
            title = (element.split(title_start))[1].split(title_end)[0]
            title.replace("\n", "")
            url = (element.split(url_start))[1].split(url_end)[0]
        if "author" in element:
            author_start = "{{"
            author_end = "}}"
            author = (element.split(author_start))[1].split(author_end)[0]
        if "urldate" in element:
            urldate_start = " \""
            urldate_end = "\""
            urldate = (element.split(urldate_start))[1].split(urldate_end)[0]
    print("\\bibitem{" + reference + "} " + author + ", \\textit{" + title + "},")
    print("")
    print("\\href{" + url + "}{" + url + "}")
    print("")
    print("[Data dostępu: " + urldate + " r.]")
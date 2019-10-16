import ast
import HTMLParser
import re
import sys
import requests
import time
import string

API_URL = "https://api.stackexchange.com"
HTML_PARSER = HTMLParser.HTMLParser()
SEPARATOR_1 = "===================================================="
SEPARATOR_2 = "----------------------------------------------------"
SEPARATOR_3 = "####################################################"

def get_segment(input_string, starting_index=0, ending_index=0, beginning_token="(", ending_token=")", escape=True):
    if beginning_token == ending_token or starting_index >= len(input_string)-1 or starting_index < 0:
        return ""
    if ending_index <= starting_index or ending_index >= len(input_string):
        ending_index = len(input_string)    
    if ending_index <= 0:
        return ""
    
    s = []
    output_starting_index = starting_index
    output_ending_index = ending_index
    found_first_beginning_token = False
    for match_oject in re.finditer(r'({})|({})'.format(re.escape(beginning_token), re.escape(ending_token)), input_string[starting_index:ending_index]):
        token = match_oject.group(0)
        if match_oject.group(0) == beginning_token:
            if not found_first_beginning_token:
                output_starting_index = match_oject.start()
                found_first_beginning_token = True
            s.append(token)
        elif match_oject.group(0) == ending_token:
            s.pop()
        if len(s) == 0:
            output_ending_index = match_oject.start() + len(ending_token)
            break
    return input_string[starting_index:ending_index][output_starting_index:output_ending_index]
    
def search_stackoverflow(query, use_similar=False):
    query = query.lower().replace("stackoverflow.", "").replace("_", " ")
    if use_similar:
        ans = requests.get(API_URL + "/similar", {
            "order": "desc",
            "sort": "relevance",
            "tagged": "python",
            "site": "stackoverflow",
            "title": query,
        }).json()
    else:
        ans = requests.get(API_URL + "/search", {
            "order": "desc",
            "sort": "votes",
            "tagged": "python",
            "site": "stackoverflow",
            "intitle": query,
        }).json()
    time.sleep(0.04)
    if not ans["items"]:
        raise ImportError("Couldn't find any question matching `" + query + "`")
    return ans

def fetch_code(url):
    q = requests.get(url)
    time.sleep(0.04)
    return q

def get_upvote_count(x):
    try:
        return int(re.search(r'itemprop="upvoteCount".+?data-value="(-?\d+)"', x).group(1))
    except:
        return 0

def normalize_code(input_string):
    if len(input_string.strip()) == 0:
        return input_string
        
    non_blank_lines = 0
    first_line_has_whitespace = False
    base_whitespace_value = ""
    for line in input_string.splitlines(True):
        line_whitespace_value = ""
        if len(line.strip()) == 0:
            continue
        non_blank_lines += 1
        for character in line:
            if character not in string.whitespace:
                break  
            line_whitespace_value += character
        if len(line_whitespace_value) > 0:
            if non_blank_lines == 1:
                first_line_has_whitespace = True
            base_whitespace_value = line_whitespace_value
            break
                    
    if len(base_whitespace_value) == 0:
        return "".join(["# "+line if line.strip().startswith(">") else line for line in input_string.splitlines(True)])
    
    return "".join([line if len(line.strip()) == 0 else (((((len(line)-len(line.lstrip(base_whitespace_value)))/len(base_whitespace_value))-int(first_line_has_whitespace)) * '\t') + line.lstrip(base_whitespace_value)) for line in (["# "+line if line.strip().startswith(">") else line for line in input_string.splitlines(True)])])


def parse_code_snippets(url, only_show_runable_code=True):
    html_string = fetch_code(url).text
    answers = []
    for match_object in re.finditer(r'<div id="answer-\d+"', html_string):
        answers.append(get_segment(html_string, starting_index=match_object.start(), beginning_token="<div", ending_token="</div"))

    for answer in sorted(answers, key=get_upvote_count, reverse=True):
        author = url
        author_profile = url
        post_link = url
        author_match = re.search('<div class="user-details" itemprop="author" itemscope itemtype="http://schema.org/Person">\s+<a href="(?P<user_profile>.+?)">.+?</a><span class="d-none" itemprop="name">(?P<user_name>.+?)</span>', answer)
        if author_match != None:
            author = author_match.group("user_name")
            author_profile = "https://stackoverflow.com" + author_match.group("user_profile")
        
        authors_code = []
        code_map = map(lambda x: x.group(1), re.finditer(r"<pre[^>]*>[^<]*<code[^>]*>((?:\s|[^<]|<span[^>]*>[^<]+</span>)*)</code></pre>", answer))
        for raw_code in sorted(code_map, key=lambda x: -len(x)):
            code = normalize_code(re.sub(r"<[^>]+>([^<]*)<[^>]*>", "\1", HTML_PARSER.unescape(raw_code)))
            try:
                ast.parse(code)
                authors_code.append(code)
            except:
                if not only_show_runable_code:
                    authors_code.append(code)
                pass
        if len(authors_code) > 0:
            print("{}\n[+] Snippets from:\n\t{}\n{}\n".format(SEPARATOR_1, author_profile, SEPARATOR_2))
            for code_snippet in authors_code:
                print("{}\n{}\n".format(code_snippet, SEPARATOR_2))
            print("{}\n\n".format(SEPARATOR_1))


def divine_truths_from_the_ether(query, question_limit=0, only_show_runable_code=True, use_similar=False):
    questions = search_stackoverflow(query, use_similar)["items"]
    questions_checked = 0
    for question in questions:
        print("{}\n#THREAD: {}\n#TITLE: {}\n#SCORE: {}\n#VIEWS:{}\n".format(SEPARATOR_3, question["link"], question["title"], question["score"], question["view_count"]))        
        parse_code_snippets(question["link"], only_show_runable_code)
        questions_checked += 1
        if question_limit > 0 and questions_checked >= question_limit:
            break      

#parse_code_snippets("https://stackoverflow.com/questions/4183506/python-list-sort-in-descending-order")
divine_truths_from_the_ether("quick sort", 5, True, True)

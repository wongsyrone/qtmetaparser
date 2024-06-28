# qtmetaparser

an ida script to parse the qt 5 metadata, including the class, method.

## Usage

Tested on IDA Pro 8.3 Portable (IDAPython v7.4.0 Python 3.11.7)

Wait until the initial IDA analysis is finished, then Run script file and select qtmetaparser.py. Done!

<del>Move the cursor to the start of qt metaobject (usually in the .data segment), run the script.</del>

qt metaobject looks like:  
![](https://raw.githubusercontent.com/xzefeng/qtmetaparser/master/img/qtmetaobject.png)


after running the script:  
![](https://raw.githubusercontent.com/xzefeng/qtmetaparser/master/img/qtmetaobject_parsed.png)
![](https://raw.githubusercontent.com/xzefeng/qtmetaparser/master/img/qtmetaobjectprivate_parsed.png)
## TODO
Everything except stringdata, method :)

# gobot-extract-secretkey
用py文件简单获取gobot引擎exe产生的密钥  
之前尝试逆向一个gobot写的游戏，无奈游戏加密的代码段过多（数值加密之类的），最后想着直接逆向获取源文件  
在github上有可用的直接获取gobot源文件的项目，但是无法直接用它获取key（如果gobot游戏加密）  
吾爱破解论坛上的确有教如何获取secretkey的，主要原理是用idapro获取key，查找gdscript::load_byte_code 函数  
然而并不是所有游戏都能找到这个函数    
然后我使用了另一个github项目去提取key （https://github.com/Vealending/Godot-AES-key-extractor）（可以去这个项目下看看原理）但是对于我的游戏似乎在提取这个二进制文件出了问题  
源代码用的是life库提取pe文件，于是我最后换了一个库，用pefile 解析 .exe 文件，然后成功了。  

用法：在脚本中编辑变量以指向要分析的二进制文件。FILE_NAME （比如exe文件），记得导入依赖库  
查找时间可能较慢  

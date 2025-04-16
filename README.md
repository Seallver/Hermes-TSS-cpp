# 说明

- 本项目基于[multi-party-sig-cpp](https://github.com/Safeheron/multi-party-sig-cpp)编写.multi-party-sig-cpp实现了3种门限签名算法：GG18,GG20和CMP.详见[multi-party-sig-cpp_readme](./multi-party-sig-cpp/multi-party-sig-cpp_README.md).
- 在src\Li24目录中实现了我们的门限签名算法,包括密钥生成和签名.我们通过Protobuf为每一轮定义了结构化数据,以实现高效的消息传输.MPC协议中使用的加密原语在safeheron-crypto-suites-cpp中定义.
- 在test目录中编写了测试样例.

# 依赖项

- [GoogleTest](https://github.com/google/googletest). GoogleTest是Google 开发的一个开源的 C++ 单元测试框架.你需要他来运行测试程序.其安装请见[GoogleTest Installation Instructions](./multi-party-sig-cpp/GoogleTest-Installation.md).
- [OpenSSL](https://github.com/openssl/openssl#documentation).OpenSSL 是一个开源的密码学工具包.其安装请见 [OpenSSL Installation Instructions](./multi-party-sig-cpp/OpenSSL-Installation.md).
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git).Protocol Buffers是Google 开发的一种高效的序列化数据交换格式. 这里我们要求版本须为 v3.14.x .其安装请见 [Protocol Buffers Installation Instructions](./multi-party-sig-cpp/Protocol-Buffers-Installation.md).
- [safeheron-crypto-suites-cpp](https://github.com/safeheron/safeheron-crypto-suites-cpp). safeheron-crypto-suites-cpp是一个开源的 C++ 密码学工具包.其安装请见 [Install safeheron-crypto-suites-cpp](https://github.com/Safeheron/safeheron-crypto-suites-cpp/blob/main/README.md).

# 支持曲线

虽然multi-party-sig-cpp扩展了对STARK曲线的支持,但本项目仅支持SECP256k1和P256曲线.

# t的含义

在进行(t,n)签名时，n代表总共参与方.

t有两种含义:

1. 恢复秘密所需的最小参与方数目
2. 恶意参与方的最大数目,即无法恢复秘密的参与方集合的最大大小.

在论文中,我们的t使用第二种含义.但是multi-party-sig-cpp使用的是第一种含义,我们在实现算法时选择与multi-party-sig-cpp保持一种,使用第一种含义.

# 测试样例

在test\Li24目录中实现了测试，包括多线程密钥生成和签名，对于密钥生成阶段，样例中给出的是(3,4)签名所需要的密钥生成，测试通过会把各方生成的密钥和种子份额等输出

对于签名阶段，我们的样例用的是(4,5)签名方案，所需要的密钥已提前生成，而且都是以base64编码形式输入的。在签名开始时，一些依赖库里的函数能够把base64编码转换成字节流，然后把字节流转换成协议规定的密钥对象，在此过程中也会对密钥形式进行检测，若最终生成的密钥对象不符合(t,n)的规定则无法通过，这是密钥对象在密钥生成和进行签名之间传递的一种方式，得到密钥对象后便可根据密钥对象的信息进行签名。



# 时间测量

在test\time目录中实现了对签名时间的测量

- 分别对cmp，gg18，gg20，Li24签名方案都实现了时间测量，测量文件存放在相应目录
- 对每种签名方案分别实现了多线程签名和单线程签名的时间测量，多线程测量文件名含有"mt"标识
- 其中key_gen测量文件用来生成签名需要的密钥并写入txt文件

大致测量方式是先确定测量轮次，确定是进行(t,n)还是(n,n)签名形式，然后确定n的范围，测量每个n下签名的总时间，进行t次求平均值。

另外可以通过修改测量代码中一些参数进行一定程度自定义的测量：

| 参数         | 含义                         |
|:----------:|:-------------------------- |
| MAX_SIZE   | n范围下限                      |
| MIN_SIZE   | n范围上限                      |
| IS_NN      | 置1进行(n,n)签名，置0进行(t,n)签名    |
| TURNS      | 测量的轮次，最后的时间取平均             |
| SLEEP_TIME | 多线程测试时为消除等待消息时间开销进行的睡眠等待时间 |

- 测试中默认设置为进行(n,n)的测试，而且n的范围为5到16
- 当进行(t,n)签名时，t取值默认为n/2向上取整
- 在进行(n,n)签名时，还是用的(t,n)测量方法，只不过令t=n
- 在进行多线程签名时间测量时，为了消除各个线程等待消息造成的时间开销，在测试每一个round之前先令进程睡眠一定时间，确保开始测量时各个线程能立刻进行签名。经检验，发现当睡眠等待时间为1.5s能确保每个线程每个round开始时收到所有消息
- 当修改签名的参数时也要在key_gen代码中作出相应的修改并重新运行，否则密钥会不匹配
- 输出的时间单位均为秒
- 在多线程测量时，是先遍历n对每个n情况下SECP256k1进行测量，之后再遍历一次n对每个n的P256进行测量，在单线程测时则是只遍历一次n对于每个n先测SECP256k1再测P256，二者时间输出方式有所不同
- gg20和gg18使用相同的密钥形式，因此gg20没有单独的key_gen，测试时它可以利用gg18的key_gen进行密钥生成

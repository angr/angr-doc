# angr 是什么？该如何使用？

angr 是一个多架构二进制分析工具集，整合了动态符号执行（像 Mayhem、KLEE 等）和各种二进制静态分析的技术。如果你想了解如何使用 angr，那就继续阅读吧！

We've tried to make using angr as pain-free as possible - 我们的目标是建立一个用户友好的二进制分析工具集，使得用户可以简单地通过 iPython 中执行几个命令来完成复杂的二进制分析工作。话虽如此，但二进制分析工作毕竟是复杂的，angr 其实也是复杂的。这份文档旨在提供关于 angr 的表述，帮助您探索、理解 angr 的设计。

试图将二进制分析工作可编程化有以下几个难点：

* 分析程序可以正确加载二进制程序
* 将二进制程序翻译成中间表示（IR）
* 实际分析工作中，可能还有如下情形：
  * 部分、全程序静态分析（如依赖分析、程序切片）
  * 程序状态空间的符号执行探索（如“我们可以一直执行，直到发现溢出吗？”）
  * 上述技术的一些组合（如“只执行那些存在内存写入的程序切片，直到发现溢出。”）

angr 提供许多组件可以很好的满足这些需要，这份文档将解释各个组件是如何工作的，以及如何利用这些组件来完成你的目的

## 开始使用

安装说明可以在 [这里](./INSTALL.md) 找到

要更深入的理解 angr 的功能，需要从 [顶层设计](./docs/toplevel.md) 入手

这份文档的可搜索 HTML 版托管在 [docs.angr.io](http://docs.angr.io/) 上，API 参考的 HTML 页面托管在 [angr.io/api-doc](http://angr.io/api-doc/) 上。

## 引用

如果您要在学术研究中使用 angr，请引用如下的论文

```bibtex
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Andrew and Grosen, John and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, John and Salls, Christopher and Dutcher, Andrew and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}
```

## 寻求帮助

要获得帮助，您可以通过以下方式：

* 邮件列表： angr@lists.cs.ucsb.edu
* slack 频道： [angr.slack.com](https://angr.slack.com)，您可以在 [这里](http://angr.io/invite.html) 注册一个账户
* IRC 频道： **\#angr** 在 [freenode](https://freenode.net/)
* 在 GitHub 上开一个新的 issue 页

## 进一步了解

您可以阅读这篇 [论文](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf) 来进一步了解 angr，这篇论文解释了内部设计、算法和使用的相关技术,这样可以帮助您进一步了解 angr

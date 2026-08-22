# AI Scanner Bench

We increase normal coverage by feeding with real requests the native Burp Audit functionality. The code define over 30 deterministic oracles, each proving a vulnerability class with a boolean, timing, out-of-band or cross-user differential result. The LLM extends its helps in the discovery when a black-box crawl falls short due to technical limitations or when having to go through multiple steps. The benefit of having a minimum harness of addtional dynamic testing allows the results to become reproducible. We practice against a set of vulnerable containers (Juice Shop, WebGoat, DVWA, [etc](https://github.com/farnaboldi/ai-scanner/blob/main/bench/e2e-matrix.sh))


## Case study: OWASP Juice Shop

We compared the following:

|   #    | Configuration            | What actually runs                                                                                           |
|--------|--------------------------|--------------------------------------------------------------------------------------------------------------|
| **#1** | **No extension**         | Burp's own crawler and built-in active audit only                                                            |
| **#2** | **AI Scanner**           | (DAST) Autonomous crawling LLM assisted and active audit                                                     |
| **#3** | **AI Scanner with Code** | (DAST+SAST) The previous plus code and prompts to surface paths from the code the crawl may never reach      |

Juice Shop reports which of its challenges have been exploited, independent of the scanner claims. This are the results:

| Metric                                       | #1 - No extension | #2 - AI Scanner | #3 - AI Scanner with Code |
|----------------------------------------------|------------------:|----------------:|--------------------------:|
| **Challenges solved**                        | 2                 | 17              | 21                        |
| **Confirmed HIGH/MED**                       | 0                 | 22              | 23                        |
| **Burp dashboard issues (total / HIGH)**     | 12 / 0            | 345 / 3         | 448 / 3                   |
| **HTTP requests sent**                       | 1,733             | 3,545           | 4,900                     |
| **Time**                                     | 3m 05s            | 29m 02s         | 33m 40s                   |
| **Source routes harvested / added to probe** | —                 | —               | 104 / 85                  |

![Increase Web Pentest Coverage using a Local LLM](https://files.catbox.moe/9a8iui.png)


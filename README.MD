### Phishing Detection from URLs via Ternary Search Trees and N-grams


I create a phishing detection system by utilizing web page URLs as a source of information. I extract discriminative character n-grams having various lengths such as 3, 4, and 5. During the implementation, I also benefit from Ternary Search Trees for storing significant n-grams along with their
weights which will be later used to classify whether a suspicious URL is phishing or legitimate.

Application should first process 4 text files (i.e. “legitimate-train.txt“, ”legitimate-test.txt”, “phishing-train.txt” and “phishing-test.txt”). These files will include varying length web page
URLs belonging to either phish or legitimate web pages. 

***Based on console application***

![phishing](https://user-images.githubusercontent.com/72974967/107271350-26c6d600-6a5d-11eb-8ee2-d3825e4fc34e.png)

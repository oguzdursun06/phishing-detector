import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

class TernaryNode {

	 public char data;     // Each node holds a char
	 public boolean isEnd;        // True if this character is last character of one of the words 
	 public TernaryNode left, middle, right;   //Subtrees
	 public int legitimate_occurrence = 0, phishing_occurrence = 0;
	 public float weight=0;     //Each node have PO,LO and weight.
	 public TernaryNode(char c) {
	  super();
	  this.data = c;
	 }

	}

public class TST {
	 public TST() {
		 System.out.println("n-gram based phishing detection via TST");
	 }
	 public TernaryNode root;         //
	 public int treeSize = 0;
	 public int featureSize;     //Console app
	 public int n_gram_size;
	 public int legitimateTrainIns = 0, legitimateTestIns = 0, phishingTrainIns = 0, phishingTestIns = 0;  //Lines of given files
	 public ArrayList<List<String>> legitimateFeatures;  //2D Arraylist for sorting.
	 public ArrayList<List<String>> phishingFeatures;
	 public ArrayList<List<String>> allWeights;
	 public int tp = 0, fn = 0, tn = 0, fp = 0, up = 0, ul = 0;
	 
	 public void insert(String word,String mod) {
	  root = insert(root, word.toCharArray(), 0,mod);
	 }

	
	 private TernaryNode insert(TernaryNode root, char[] word, int i, String mod) {
	  if (root == null) {						//Base Case: Tree is empty
	   root = new TernaryNode(word[i]);                 //create a new ternary search tree node 
	  }	
	  if (word[i] < root.data)   //If current character of word is smaller than root's character, insert left
	   root.left = insert(root.left, word, i,mod);
	  else if (word[i] > root.data)
	   root.right = insert(root.right, word, i,mod);    //if greater
	  else
		//If current character of word is same as root's character
	  {
	   if (i + 1 < word.length)             // If it is not the last letter of the word
	    root.middle = insert(root.middle, word, i + 1,mod);
	   else {  //Last letter
		   if(root.isEnd == true && mod.equals("legitimate"))             //If last letter and legitimate, LO++
			   root.legitimate_occurrence++;
		   else if(root.isEnd == true && mod.equals("phishing"))		//If last letter and phishing, PO++
			   root.phishing_occurrence++;
		   else if(root.isEnd == false && mod.equals("legitimate")) {
			   root.legitimate_occurrence = 1;
		   	   root.isEnd = true;
		   }
		   else {
			   root.phishing_occurrence = 1;
		   	   root.isEnd = true;           
		   }
		   
	   }
	  }
	  return root;
	 }

	 public void buildTree(String file,TST tst,String mod) throws IOException {
		 BufferedReader br = new BufferedReader(new FileReader(file));
		 String line;
		 
		 while ((line = br.readLine()) != null) {
			 line = line.replace("https", "");    //https http www must remove from every url
			 line = line.replace("http", "");        
			 line = line.replace("www", "");
			 if(mod.equals("legitimate")) {
				 for (int i = 0; i < line.length() - tst.n_gram_size + 1; i++)
			        tst.insert(line.substring(i, i + tst.n_gram_size).toLowerCase(Locale.ENGLISH),mod); 
				 tst.legitimateTrainIns++;
			 }
			 if(mod.equals("phishing")){
				 for (int i = 0; i < line.length() - tst.n_gram_size + 1; i++)
			        tst.insert(line.substring(i, i + tst.n_gram_size).toLowerCase(Locale.ENGLISH),mod);
				 tst.phishingTrainIns++;
			 }
			 
		 }
		 if(mod.equals("legitimate")) {     
			 legitimateFeatures = new ArrayList<List<String>>();    //A 2D array list where we will hold the data for sorting
			 legitimateFeatures = collectDataFromTST(root,"","legitimate");  //Traverse tree and load all legitimate
		 }
		 else {
			 phishingFeatures = new ArrayList<List<String>>();
			 phishingFeatures = collectDataFromTST(root,"","phishing");     ////Traverse tree and load all phishing
		 }
		
		 
		 
	 }
	
	    public ArrayList<List<String>> collectDataFromTST(TernaryNode iterator, String str,String mod)
	    {   // This is a traversing algorithm. According the mode(occur or weight), collects data from the tree and add it to the list then return.
	        if (iterator != null)
	        {
	        	collectDataFromTST(iterator.left, str,mod);
	 
	            str = str + iterator.data;
	            if (iterator.isEnd) {      
	            	
	            	if(mod.equals("legitimate")) {
	            		List<String> temp = new ArrayList<String>();
		            	temp.add(str);
	            		temp.add(Integer.toString(iterator.legitimate_occurrence));
	            		legitimateFeatures.add(temp);
	            	}
	            	else if(mod.equals("phishing")){
	            		if(iterator.phishing_occurrence > 0) {
	            		List<String> temp = new ArrayList<String>();
		            	temp.add(str);
	            		temp.add(Integer.toString(iterator.phishing_occurrence));
	            		phishingFeatures.add(temp);
	            		}
	            	}
	            	else {
	            		List<String> temp = new ArrayList<String>();
		            	temp.add(str);
		            	if(iterator.phishing_occurrence > 0 && iterator.legitimate_occurrence == 0) 
		            		iterator.weight = 1;
		            	
		            	else if(iterator.phishing_occurrence == 0 && iterator.legitimate_occurrence > 0) 
		            		iterator.weight = -1;
		            	else {
		            		if(iterator.phishing_occurrence > iterator.legitimate_occurrence) 
		            			iterator.weight = (float)Math.min(iterator.phishing_occurrence, iterator.legitimate_occurrence)/(float)Math.max(iterator.phishing_occurrence, iterator.legitimate_occurrence);
		            		else if(iterator.phishing_occurrence < iterator.legitimate_occurrence)
		            			iterator.weight = -1 * (float)Math.min(iterator.phishing_occurrence, iterator.legitimate_occurrence)/(float)Math.max(iterator.phishing_occurrence, iterator.legitimate_occurrence);
		            		else
		            			iterator.weight = 0;
		            	}
		            	temp.add(String.valueOf(iterator.weight));
		            	treeSize++;
		            	allWeights.add(temp);	
	            	}
	            	
	            }
	 
	            collectDataFromTST(iterator.middle, str,mod);
	            str = str.substring(0, str.length() - 1);
	 
	            collectDataFromTST(iterator.right, str,mod);
	        }
	        if(mod.equals("legitimate"))
	        	return legitimateFeatures;
	        else if(mod.equals("phishing")) {
	        	return phishingFeatures;
	        }
	        else {
	        	return allWeights;
	        }
	    }
	    
	  //Print all the elements up to the given feature size.
	    public void printStrong(PrintWriter write, ArrayList<List<String>> sortedArray,String mod){    	
	    	for(int i = 0; i < featureSize; i++) {   
	    		if(mod.equals("legitimate"))
	    			write.write(i+1+". "+sortedArray.get(i).get(0)+" -  freq: "+getFrequencyFromTST(root, sortedArray.get(i).get(0).toCharArray(), 0,"legitimate")+"\n");
	    		else {
	    			write.write(i+1+". "+sortedArray.get(i).get(0)+" -  freq: "+getFrequencyFromTST(root, sortedArray.get(i).get(0).toCharArray(), 0,"phishing")+"\n");
	    		}
	    	}
	    	
	    }
	    //2D Arraylist sorting method
	    public void sortByFreq(ArrayList<List<String>> sortByFrequency) {
	    	Collections.sort(sortByFrequency, new Comparator<List<String>>() {    
	            @Override
	            public int compare(List<String> o1, List<String> o2) {
	                return Integer.compare(Integer.parseInt(o2.get(1)),(Integer.parseInt(o1.get(1)))); 
	            }       
	    	});
	    }
	    
	    public void printAllWeight(PrintWriter write, ArrayList<List<String>> sortByFrequency){
	    	Collections.sort(sortByFrequency, new Comparator<List<String>>() {    
	            @Override
	            public int compare(List<String> o1, List<String> o2) {
	                return Float.compare(Float.parseFloat(o2.get(1)),(Float.parseFloat(o1.get(1))));
	            }       
	    	});
	    	write.write("All N-Gram Weights\n");
	    	for(int i = 0; i < sortByFrequency.size(); i++) {
	    			write.write(sortByFrequency.get(i).get(0)+" -  weight: "+sortByFrequency.get(i).get(1)+"\n");
	    		}
	    	
	    	
	    	
	    	
	    }
	    public void delete(String word)
	    {
	        delete(root, word.toCharArray(), 0);
	    }
	    // function to delete a word 
	    private void delete(TernaryNode iterator, char[] word, int ptr)
	    {
	        if (iterator == null)
	            return;
	 
	        if (word[ptr] < iterator.data)
	            delete(iterator.left, word, ptr);
	        else if (word[ptr] > iterator.data)
	            delete(iterator.right, word, ptr);
	        else
	        {
	            // to delete a word just make isEnd false 
	            if (iterator.isEnd && ptr == word.length - 1) {
	                iterator.isEnd = false;
	                treeSize--;
	            }
	 
	            else if (ptr + 1 < word.length)
	                delete(iterator.middle, word, ptr + 1);
	        }        
	    }
	    public int getFrequencyFromTST(TernaryNode tree,char[] word, int ptr,String mod) {
	    	// This is a searching algorithm in TST. Function that finds the word and returns its frequency according the mode.
	            TernaryNode temp = tree;
	    		if (temp == null)
	                return -1;
	            while(temp != null) {
	            if (word[ptr] < temp.data)
	                temp = temp.left;
	            else if (word[ptr] > temp.data)
	                temp = temp.right;
	            else
	            {
	                if (temp.isEnd && ptr == word.length - 1) {
	                	if(mod.equals("legitimate"))
	                		return temp.legitimate_occurrence;
	                	else
	                		return temp.phishing_occurrence;
	                }
	                else if (ptr == word.length - 1)
	                    return -1;
	                else {
	                    ptr++;
	                	temp = temp.middle;
	                }
	            }        
	            }
	            return -1;
	    }
	    
	    public float getWeightFromTST(TernaryNode tree,char[] word, int ptr) {
	    	
            TernaryNode temp = tree;
    		if (temp == null)   //If not, let's assume weight -2. We must check caller function.
                return -2;
            while(temp != null) {
            if (word[ptr] < temp.data)
                temp = temp.left;
            else if (word[ptr] > temp.data)
                temp = temp.right;
            else
            {
                if (temp.isEnd && ptr == word.length - 1) {
                	return temp.weight;
                }
                else if (ptr == word.length - 1) //If not, let's assume weight -2. We must check caller function.
                    return -2;
                else {
                    ptr++;
                	temp = temp.middle;
                }
            }        
            }
            return -2;
    }
	    public void removeUnnecessary(TernaryNode iterator,String str, int lastFreqL, String lastStringL, int lastFreqP, String lastStringP) {
	    	// The parameters are the boundary points of the arraylists we keep in ordered, according to the feature size.
	    	if (iterator != null)
	        {
	            removeUnnecessary(iterator.left, str,lastFreqL,lastStringL, lastFreqP,lastStringP);
	 
	            str = str + iterator.data;
	            if (iterator.isEnd) {               //occurrences is less than or equal to the any boundary
	            	if(iterator.legitimate_occurrence <= lastFreqL && iterator.phishing_occurrence <= lastFreqP) {
	            		if((iterator.legitimate_occurrence == lastFreqL && str.compareTo(lastStringL) <= 0) || (iterator.phishing_occurrence == lastFreqP && str.compareTo(lastStringP) <= 0)) {
	            		}        //Nothing happened, just easy way for else 
	            			
	            		else {    //This is an unnecessary ngram. It comes out of the tree.
	            			delete(str);
	            		}
	            	} 
	            	
	            }
	 
	            removeUnnecessary(iterator.middle, str,lastFreqL,lastStringL, lastFreqP,lastStringP);
	            str = str.substring(0, str.length() - 1);
	 
	            removeUnnecessary(iterator.right, str,lastFreqL,lastStringL, lastFreqP,lastStringP);
	        }
	    	
	    
	    	
	    }
	    
	    public void testingStage(String file,TST tst,String mod) throws IOException {
			 BufferedReader br = new BufferedReader(new FileReader(file));
			 String line;
			 
			 while ((line = br.readLine()) != null) {
				 line = line.replace("https", "");
				 line = line.replace("http", "");
				 line = line.replace("www", "");
				 	 float sumOfLine = 0;
					 for (int i = 0; i < line.length() - tst.n_gram_size + 1; i++) {
						 float ngram_weight = tst.getWeightFromTST(tst.root, line.substring(i, i + tst.n_gram_size).toLowerCase(Locale.ENGLISH).toCharArray(), 0);
						 if(ngram_weight != -2.0) {
							 sumOfLine += ngram_weight;
						 }
					 }
					 if(mod.equals("legitimate")) {
						 	if(sumOfLine > 0)
						 		fp++;     // URL is legitimate but the prediction was wrongly made – saying it is phishing.
						 	else if(sumOfLine < 0) {
						 		tn++;     // URL is legitimate and the prediction is also true saying it is legitimate.

						 	}
						 	else {    
						 		ul++;         // URL is legitimate but computed total score is zero.
						 	}
						 	tst.legitimateTestIns++;	//line number
					 }
					 else {
						 if(sumOfLine > 0)
						 		tp++;      // URL is phishing  and predicted is also true saying it is phishing.

						 	else if(sumOfLine < 0) {
						 		fn++;  // URL is phishing but the prediction was wrongly made – saying it is legitimate.
						 	}
						 	else {
						 		up++;      //URL is legitimate but computed totalscore is zero.
						 	}
						 tst.phishingTestIns++;      //phishingtest line number
					 }
			
			 } 
			 
		 }

	}


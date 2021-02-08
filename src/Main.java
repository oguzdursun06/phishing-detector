import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {

	 public static void main(String[] args) throws IOException {
		  TST tst = new TST();                               // TST object created.
		  Scanner scan = new Scanner(System.in);
		  System.out.print("feat_size: ");
	      tst.featureSize = scan.nextInt();       // This method reads the number provided using keyboard
	      System.out.print("n_gram_size: ");
	      tst.n_gram_size = scan.nextInt(); 
		  tst.buildTree("legitimate-train.txt",tst,"legitimate");          // All legitimate n-grams were placed on the tree. 
		  tst.sortByFreq(tst.legitimateFeatures);						//	The legitimate n-gram arraylist created in the above function sorted.
		  tst.buildTree("phishing-train.txt",tst,"phishing");            //All phishing n-grams were placed on the tree.
		  tst.sortByFreq(tst.phishingFeatures);										//Arraylist sorted by frequency.
		  tst.allWeights = new ArrayList<List<String>>();
		  tst.allWeights = tst.collectDataFromTST(tst.root,"","computeWeight");     // Calculate the weight of all n-grams and keep them in an arraylist to sort.
		  int oldTreeSize = tst.treeSize;       //Tree size before removing the unnecessary 
		  tst.removeUnnecessary(tst.root, "", Integer.parseInt(tst.legitimateFeatures.get(tst.featureSize-1).get(1)), tst.legitimateFeatures.get(tst.featureSize-1).get(0), Integer.parseInt(tst.phishingFeatures.get(tst.featureSize-1).get(1)), tst.phishingFeatures.get(tst.featureSize-1).get(0));
		  tst.testingStage("legitimate-test.txt", tst, "legitimate");     //Test the defaults as legitimate.
		  tst.testingStage("phishing-test.txt", tst, "phishing");         //Test the defaults as phishing.
		  System.out.println("Legitimate training file has been loaded with ["+tst.legitimateTrainIns+"] instances");
		  System.out.println("Legitimate test file has been loaded with ["+tst.legitimateTestIns+"] instances");
		  System.out.println("Phishing training file has been loaded with ["+tst.phishingTrainIns+"] instances");
		  System.out.println("Phishing test file has been loaded with ["+tst.phishingTestIns+"] instances");
		  System.out.println("TST has been loaded with "+tst.legitimateTrainIns+" n-grams");
		  System.out.println("TST has been loaded with "+tst.phishingTrainIns+" n-grams");
		  File newFile = new File("strong_legitimate_features.txt");
		  PrintWriter write = new PrintWriter(new FileWriter(newFile, false));
		  write.write("Most important legitimate n_grams\n");
		  tst.printStrong(write,tst.legitimateFeatures,"legitimate");            //First feature size element's of legitimate n-grams.
		  write.close();;
		  File newFile1 = new File("strong_phishing_features.txt");
		  PrintWriter write1 = new PrintWriter(new FileWriter(newFile1, false)); 
		  write1.write("Most important phishing n_grams\n");
		  tst.printStrong(write1, tst.phishingFeatures,"phishing");               //First feature size element's of phishing n-grams.
		  System.out.println(tst.featureSize+" strong phishing n-grams have been saved to the file \"strong_phishing_features.txt\"");
		  System.out.println(tst.featureSize+" strong legitimate n-grams have been saved to the file \"strong_legitimate_features.txt\"");
		  write1.close();
		  File newFile2 = new File("all_feature_weights.txt");
		  PrintWriter write2 = new PrintWriter(new FileWriter(newFile2, false));
		  tst.printAllWeight(write2, tst.allWeights);
		  System.out.println(oldTreeSize+" n-grams + weights have been saved to the file \"all_feature_weights.txt\"");
		  int newTreeSize = tst.treeSize;      //Tree size only when significant n-grams are in the tree
		  System.out.println(oldTreeSize-newTreeSize+" insignificant n-grams have been removed from the TST");
		  write2.close();
		  System.out.print("TP:"+tst.tp+" FN:"+tst.fn+" TN:"+tst.tn+" FP:"+tst.fp+ " Unpredictable Phishing:"+tst.up+" Unpredictable Legitimate:"+tst.ul);
		  System.out.println("\nAccuracy: "+(float)(tst.tp+tst.tn)/(float)(tst.tp+tst.tn+tst.fp+tst.fn+tst.up+tst.ul));
		 }

}

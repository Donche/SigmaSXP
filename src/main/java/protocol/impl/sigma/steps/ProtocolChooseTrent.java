package protocol.impl.sigma.steps;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.ListIterator;

import javax.xml.bind.annotation.XmlElement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;

import controller.Users;
import controller.tools.JsonTools;
import crypt.factories.ElGamalAsymKeyFactory;
import model.entity.ElGamalKey;
import model.entity.User;
import network.api.EstablisherService;
import network.api.EstablisherServiceListener;
import network.api.Peer;
import protocol.impl.SigmaEstablisher;
import protocol.impl.sigma.SigmaContract;

/**
 * Choose Trent with the other peers for this contract
 * @author neon@ec-m.fr chen.dang@etu.univ-amu.fr
 * 
 * The format of data sent here is a String[2] with
 * 		data[0] = round
 * 		data[1] = jsonSent
 *
 *	First round - setup a list of potential TTP
 *	Second round - choose a random TTP
 *	Third round - checks that everyone has same TTP
 */

public class ProtocolChooseTrent implements ProtocolStep {
	
	public static final String TITLE  = "CHOOSING_TRENT";
	public static final BigInteger P = new BigInteger ("124233341635855292420681698148845681014844866056212176632655173602444135581779341928584451946831820357622587249219477577145009300106828967466602146104562163160400103396735672041344557638270362523343149686623705761738910044071399582025053147811261321814632661084042311141045136246602979886564584763268994320823");
	public static final BigInteger G = new BigInteger ("57879985263161130068016239981615161174385902716647642452899971198439084259551250230041086427537114453738884538337956090286524329552098304591825815816298805245947460536391128315522193556464285417135160058086869161063941463490748168352401178939129440934609861888674726565294073773971086710395310743717916632171");
	
	@XmlElement(name="list")
	final private ArrayList<User> list;
	
	@XmlElement(name="ra")
	private BigInteger ra;
	private BigInteger gra;
	private BigInteger grb;
	private BigInteger grab;
	private BigInteger grba;
	@XmlElement(name="finalNumber")
	private BigInteger finalNumber;
	
	@XmlElement(name="hasSent")
	private String[][] hasSent = new String[4][];
	

	@XmlElement(name="key")
	private ElGamalKey key;
	
	private SigmaEstablisher sigmaE;
	private Peer peer;
	private HashMap<ElGamalKey,String> uris;
	private EstablisherService es;
	private SigmaContract contract;
	private int senderKeyId;

	final private JsonTools<Collection<User>> json = new JsonTools<>(new TypeReference<Collection<User>>(){});
	final private JsonTools<String[]> jsonMessage = new JsonTools<>(new TypeReference<String[]>(){});
	
	/**
	 * Used when the protocol stopped and need to be restarted from scratch where it stopped
	 */
	
	@JsonCreator
	public ProtocolChooseTrent(@JsonProperty("list") ArrayList<User> list,
			@JsonProperty("ra") BigInteger ra,
			@JsonProperty("finalNumber") BigInteger finalNumber,
			@JsonProperty("hasSent") String[][] hasSent,
			@JsonProperty("key") ElGamalKey key){
		this.list = list;
		this.ra = ra;
		this.finalNumber = finalNumber;
		this.hasSent = hasSent;
		this.key = key;
		
		this.senderKeyId = 0;
		String senPubK = key.getPublicKey().toString();
		while (!(contract.getParties().get(this.senderKeyId).getPublicKey().toString().equals(senPubK))){this.senderKeyId++;}
	}
	
	/**
	 * Constructor for the step
	 * @param sigmaE : the current sigmaEstablisher it is started from
	 * @param key : signer key
	 */
	public ProtocolChooseTrent(SigmaEstablisher sigmaE,
			ElGamalKey key){
		
		this.key = key;
		this.sigmaE = sigmaE;
		this.peer = sigmaE.peer;
		this.uris = sigmaE.sigmaEstablisherData.getUris();
		this.es = sigmaE.establisherService;
		this.contract = sigmaE.sigmaEstablisherData.getContract();
		assert(contract != null);
		// Setup list of users (remove the signers)
		this.list = new ArrayList<User>(json.toEntity((new Users()).get()));
		for (ElGamalKey k : contract.getParties()){
	        ListIterator<User> it = list.listIterator();  
			while(it.hasNext())
				if (k.getPublicKey().equals(it.next().getKey().getPublicKey()))
					it.remove();
		}	

		// Setup the random number which will be sent

		int i=0;
		String senPubK = key.getPublicKey().toString();
		while (!(contract.getParties().get(i).getPublicKey().toString().equals(senPubK))){i++;}
		for (int k=0; k<hasSent.length; k++)
			hasSent[k] = new String[contract.getParties().size() + 1];
		this.senderKeyId = i;

		// Setup the listener on other peers
		this.setupListener();
	}
	
	@Override
	/**
	 * Called to start again
	 */
	public void restore(SigmaEstablisher sigmaE){
		this.sigmaE = sigmaE;
		this.peer = sigmaE.peer;
		this.uris = sigmaE.sigmaEstablisherData.getUris();
		this.es = sigmaE.establisherService;
		this.contract = sigmaE.sigmaEstablisherData.getContract();
		
		this.setupListener();
	}
	
	
	@Override
	public String getName() {
		return TITLE;
	}

	
	@Override
	/*
	 * The round here is 
	 * 		+ 0 if the list hasn't been setup with other peers
	 * 		+ 1 if the random numbers aren't sent
	 * 		+ 2 if the random numbers aren't recovered
	 * 		+ 3 if Trent is already chosen
	 */
	public int getRound() {
		if (Arrays.asList(hasSent[0]).indexOf(null) != (-1))
			return 0;
		else if (Arrays.asList(hasSent[1]).indexOf(null) != (-1))
			return 1;
		else if (Arrays.asList(hasSent[2]).indexOf(null) != (-1))
			return 2;
		return 3;
	}

	
	@Override
	public void sendMessage() {
		if(ra == null) {
			this.ra = new BigInteger(100, new SecureRandom());
			this.finalNumber = this.ra;
			gra = G.modPow(ra, P);			
		}
		System.out.println("user " + senderKeyId + " start: generate ra and Gra");
		String[] content = {"0", json.toJson(list)};
		String senPubK = key.getPublicKey().toString();
		assert(contract.getHashableData() != null);
		es.sendContract(TITLE+new String(contract.getHashableData()),
				jsonMessage.toJson(content), 
				senPubK,
				peer, 
				uris);
		hasSent[0][senderKeyId] = "";
	}

	
	@Override
	public void setupListener() {
		final String contractId = new String(contract.getHashableData());
		final String senPubK = key.getPublicKey().toString();
		final int N = contract.getParties().size();
		
		es.removeListener(TITLE+contractId+senPubK);
		assert(contractId != null);
		assert(senPubK != null);
		es.setListener("title", TITLE+contractId, TITLE+contractId+senPubK, new EstablisherServiceListener() {
			@Override
			public void notify(String title, String msg, String senderId) {
				String[] content = jsonMessage.toEntity(msg);
				//search sender id
				int j = 0;
				while (!(contract.getParties().get(j).getPublicKey().toString().equals(senderId))){j++;}
				// If we received a new list
				if (content[0].equals("0") && Arrays.asList(hasSent[0]).indexOf(null) != (-1)){
					//if the receiver hasn't generated the number
					if(ra == null) {
						ra = new BigInteger(100, new SecureRandom());
						finalNumber = ra;
						gra = G.modPow(ra, P);			
					}
					System.out.println("Round 0: user " + senderKeyId + " get list from user " + j);
					//remove the users who are not in common list
					Collection<User> list2 = json.toEntity(content[1]);
			        	ListIterator<User> it = list.listIterator();
					while(it.hasNext()){
						boolean isInBoth = false;
						for (User u : list2){
							if (u.getKey().getPublicKey().equals(it.next().getKey().getPublicKey()))
								isInBoth = true;
						}
						if (!isInBoth)
							it.remove();
					}
					hasSent[0][j] = "";
					//if we have received lists from all parties
					if (Arrays.asList(hasSent[0]).indexOf(null) == N){
						hasSent[0][N] = "";
						System.out.println("Round 0: user " + senderKeyId + " send its Gra to all users in contract");
						System.out.println("Round 0: user " + senderKeyId + " ready to enter round 2 ");
						String[] toBeSent = new String[2];
						toBeSent[0] = "1";
						toBeSent[1] = gra.toString();
						hasSent[1][senderKeyId] = "";
						es.sendContract(TITLE+contractId, jsonMessage.toJson(toBeSent), senPubK, peer, uris);
					}
				}
				// If we receive the others encrypted number
				else if (content[0].equals("1") && Arrays.asList(hasSent[1]).indexOf(null) != (-1)){
					// Wait for everyone to have sent their encrypted number
					if (hasSent[1][j] == null){
						hasSent[1][j] = "";
						grb = new BigInteger(content[1]);
						System.out.println("Round 1: user " + senderKeyId + " receive Grb from user "+ j);
					}
					//if we have received encrypted number from all parties
					if (Arrays.asList(hasSent[1]).indexOf(null) == N){
						System.out.println("Round 1: user " + senderKeyId + " ready to enter round 2 ");
						hasSent[1][N] = "";
						grba = grb.modPow(ra, P);
						String[] toBeSent = new String[2];
						toBeSent[0] = "2";
						toBeSent[1] = ra.toString();
						hasSent[2][senderKeyId] = "";
						es.sendContract(TITLE+contractId, jsonMessage.toJson(toBeSent), senPubK, peer, uris);
					}
				}
				// If we receive the others random number
				else if (content[0].equals("2") && Arrays.asList(hasSent[2]).indexOf(null) != (-1)){
					// Wait for everyone to have sent their number
					if (hasSent[2][j] == null){
						hasSent[2][j] = "";
						BigInteger rb = new BigInteger(content[1]);
						System.out.println("Round 2: user " + senderKeyId + " get rb from " + j);
						grab = gra.modPow(rb, P);
						finalNumber = ra.add(rb);
					}
					//if we have received random number from all parties
					if (Arrays.asList(hasSent[2]).indexOf(null) == N){
						hasSent[2][N] = "";
						list.sort(new Comparator<User>(){
							@Override
							public int compare(User u1, User u2){
								return u1.getKey().getPublicKey().compareTo(u2.getKey().getPublicKey());
							}
						});
						int N2 = (int) list.size();
						//if the number isn't correct
						if (grab.compareTo(grba) != 0){
							System.out.println("Round 2: user " + senderKeyId + " finds grab != grba, protocol cancelled");
							for (int k=0; k<hasSent.length; k++)
								hasSent[k] = new String[contract.getParties().size()];
							sigmaE.setTrent(null);
							sendMessage();
						}
						else if (N2 == 0){
							System.out.println("Can't go on - there is no third party available");
						}
						//if everything goes well
						else {
							User trentUser = list.get(finalNumber.mod(new BigInteger(String.valueOf(N2))).intValue());
							if (sigmaE.sigmaEstablisherData.getTrentKey() ==null){
								sigmaE.setTrent(trentUser.getKey());
								System.out.println("Round 2: user " + senderKeyId + " set trent");
							}
							
							String[] toBeSent = new String[2];
							toBeSent[0] = "3";
							toBeSent[1] = trentUser.getKey().getPublicKey().toString();
							hasSent[3][senderKeyId] = "";
							es.sendContract(TITLE+contractId, jsonMessage.toJson(toBeSent), senPubK, peer, uris);
							System.out.println("Round 2: user " + senderKeyId + " send trent to all users in contract");
							if (sigmaE.sigmaEstablisherData.getTrentKey() !=null &&
									!sigmaE.sigmaEstablisherData.getTrentKey().getPublicKey().equals(trentUser.getKey().getPublicKey())){
								for (int k=0; k<hasSent.length; k++)
									hasSent[k] = new String[contract.getParties().size()];
								sigmaE.setTrent(null);
								sendMessage();
							}
						}
					}
				}
				// Check that we have the same Trent
				else if (content[0].equals("3") && Arrays.asList(hasSent[3]).indexOf(null) != (-1)){
					ElGamalKey sigmakey = sigmaE.sigmaEstablisherData.getTrentKey();
					if (sigmakey==null){
						ElGamalKey trentK = ElGamalAsymKeyFactory.create(false);
						trentK.setPublicKey(new BigInteger(content[1]));
						sigmaE.setTrent(trentK);
						System.out.println("Round 3: user " + senderKeyId + " set trent key");
						hasSent[3][j] = "";
					}else if(content[1].equals(sigmakey.getPublicKey().toString())){
						hasSent[3][j] = "";
						if (Arrays.asList(hasSent[3]).indexOf(null) == (N)){
							hasSent[3][N] = "";
							System.out.println("Round 3: user " + senderKeyId + " finishes TTP protocol");
							nextStep();
						}
					}
					// if the chosen trent isn't the same
					else {
						System.out.println("Round 3: user " + senderKeyId + " trent not equal");
						for (int k=0; k<hasSent.length; k++)
							hasSent[k] = new String[contract.getParties().size()];
						sigmaE.setTrent(null);
						sendMessage();
					}
				}
			}
		}, uris != null);

	}

	@Override
	public void stop() {
		String contractId = new String(contract.getHashableData());
		String senPubK = key.getPublicKey().toString();
		es.removeListener(TITLE+contractId+senPubK.toString());
	}
	
	/**
	 * Contains what needs to be done after this step
	 */
	private void nextStep(){
		sigmaE.setListenerOnTrent();
	}

}

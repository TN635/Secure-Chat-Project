#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include <limits.h> // For HOST_NAME_MAX

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

// Global variables for session keys and shared secrets
dhKey localKey;
dhKey remoteKey;
unsigned char sessionKey[512];

// Global variables for HMAC and AES
unsigned char encryptionKey[32];  // AES key for encryption and decryption
unsigned char authKey[64];        // Key for HMAC

// Global variables for incoming/outgoing sequence numbers
unsigned long long transmittedSequence = 0;
unsigned long long receivedSequence = 0;

static GtkTextBuffer *transcriptBuffer;
static GtkTextBuffer *messageBuffer;
static GtkTextView *textView;
static GtkTextMark *textMark;

static pthread_t receiveThread;
void *receiveMessage(void *);  // For receiveThread

#define max(a, b) \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listenSocket, socketFD;
static int isClient = 1;

static void handleError(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initializeServerNetwork(int port)
{
	int reuse = 1;
	struct sockaddr_in serverAddress;
	struct sockaddr_in clientAddress;
	socklen_t clientLength;

	listenSocket = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	if (listenSocket < 0)
		handleError("ERROR opening socket");

	bzero((char *)&serverAddress, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = INADDR_ANY;
	serverAddress.sin_port = htons(port);

	if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		handleError("ERROR on binding");

	fprintf(stderr, "listening on port %i...\n", port);
	listen(listenSocket, 1);

	socketFD = accept(listenSocket, (struct sockaddr *)&clientAddress, &clientLength);
	if (socketFD < 0)
		handleError("error on accept");

	fprintf(stderr, "Server connection made, starting secure session...\n");

	// Generate DH key
	dhGenerateKey(&localKey);
	// Send public key
	sendDHKey(socketFD, &localKey);
	// Receive client's public key
	receiveDHKey(socketFD, &remoteKey);
	// Derive the shared secret
	unsigned char derivedKey[256];
	dhFinalize(localKey.SK, localKey.PK, remoteKey.PK, derivedKey, sizeof(derivedKey));

	// Load RSA keys
	RSA *rsaPrivate = loadRSAPrivateKey("server_private.pem");
	RSA *rsaPublic = loadRSAPublicKey("client_public.pem");

	// Perform mutual authentication
	sendAuthenticationChallenge(socketFD);
	receiveAndRespondToChallenge(socketFD, rsaPrivate);
	verifyRSASignature(socketFD, rsaPublic);

	close(listenSocket);
	/* at this point, should be able to send/recv on socketFD */
	return 0;
}

static int initializeClientNetwork(char *hostname, int port)
{
	struct sockaddr_in serverAddress;
	struct hostent *server;

	socketFD = socket(AF_INET, SOCK_STREAM, 0);
	server = gethostbyname(hostname);

	if (socketFD < 0)
		handleError("ERROR opening socket");

	if (server == NULL)
	{
		fprintf(stderr, "ERROR, no such host\n");
		exit(0);
	}

	bzero((char *)&serverAddress, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	memcpy(&serverAddress.sin_addr.s_addr, server->h_addr, server->h_length);
	serverAddress.sin_port = htons(port);

	if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		handleError("ERROR connecting");

	fprintf(stderr, "Connected to %s, starting secure session...\n", hostname);

	// Generate DH key
	dhGenerateKey(&localKey);
	// Send public key
	sendDHKey(socketFD, &localKey);
	// Receive server's public key
	receiveDHKey(socketFD, &remoteKey);
	// Derive the shared secret
	unsigned char derivedKey[256];
	dhFinalize(localKey.SK, localKey.PK, remoteKey.PK, derivedKey, sizeof(derivedKey));

	// Load RSA keys
	RSA *rsaPrivate = loadRSAPrivateKey("client_private.pem");
	RSA *rsaPublic = loadRSAPublicKey("server_public.pem");

	// Perform mutual authentication
	receiveAndRespondToChallenge(socketFD, rsaPrivate);
	sendAuthenticationChallenge(socketFD);
	verifyRSASignature(socketFD, rsaPublic);

	return 0;
}

static int terminateNetwork()
{
	shutdown(socketFD, 2);
	unsigned char dummy[64];
	ssize_t r;
	do
	{
		r = recv(socketFD, dummy, 64, 0);
	} while (r != 0 && r != -1);
	close(socketFD);
	return 0;
}

/* end network stuff. */

static const char *usage =
	"Usage: %s [OPTIONS]...\n"
	"Secure chat (CCNY computer security project).\n\n"
	"   -c, --connect HOST  Attempt a connection to HOST.\n"
	"   -l, --listen        Listen for new connections.\n"
	"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
	"   -h, --help          show this message and exit.\n";

static void appendToTranscript(char *message, char **tags, int ensureNewLine)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(transcriptBuffer, &t0);
	size_t len = g_utf8_strlen(message, -1);
	if (ensureNewLine && message[len - 1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(transcriptBuffer, &t0, message, len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(transcriptBuffer, &t1);
	t0 = t1;
	gtk_text_iter_backward_chars(&t0, len);
	if (tags)
	{
		char **tag = tags;
		while (*tag)
		{
			gtk_text_buffer_apply_tag_by_name(transcriptBuffer, *tag, &t0, &t1);
			tag++;
		}
	}
	if (!ensureNewLine)
		return;
	gtk_text_buffer_add_mark(transcriptBuffer, textMark, &t1);
	gtk_text_view_scroll_to_mark(textView, textMark, 0.0, 0, 0.0, 0.0);
	gtk_text_buffer_delete_mark(transcriptBuffer, textMark);
}

static void transmitMessage(GtkWidget *messageWidget, gpointer userData)
{
	char *messageTags[2] = {"self", NULL};
	appendToTranscript("me: ", messageTags, 0);

	GtkTextIter startIter, endIter;
	gtk_text_buffer_get_start_iter(messageBuffer, &startIter);
	gtk_text_buffer_get_end_iter(messageBuffer, &endIter);
	char *userMessage = gtk_text_buffer_get_text(messageBuffer, &startIter, &endIter, FALSE);
	size_t messageLength = strlen(userMessage);

	unsigned char ivBuffer[16];
	RAND_bytes(ivBuffer, sizeof(ivBuffer));  // Generate IV

	unsigned char encryptedMessage[512];
	int encryptedLength = 0;

	EVP_CIPHER_CTX *cipherContext = EVP_CIPHER_CTX_new();
	if (!cipherContext)
	{
		fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
		return;
	}

	if (EVP_EncryptInit_ex(cipherContext, EVP_aes_256_ctr(), NULL, encryptionKey, ivBuffer) != 1)
	{
		fprintf(stderr, "Encryption initialization failed\n");
		EVP_CIPHER_CTX_free(cipherContext);
		return;
	}

	if (EVP_EncryptUpdate(cipherContext, encryptedMessage, &encryptedLength, (unsigned char *)userMessage, messageLength) != 1)
	{
		fprintf(stderr, "Encryption failed\n");
		EVP_CIPHER_CTX_free(cipherContext);
		return;
	}

	int outLength;
	if (EVP_EncryptFinal_ex(cipherContext, encryptedMessage + encryptedLength, &outLength) != 1)
	{
		fprintf(stderr, "Encrypt Final failed\n");
		EVP_CIPHER_CTX_free(cipherContext);
		return;
	}
	encryptedLength += outLength;

	EVP_CIPHER_CTX_free(cipherContext);

	// Compute HMAC
	unsigned char mac[64];
	HMAC(EVP_sha512(), authKey, sizeof(authKey), encryptedMessage, encryptedLength, mac, NULL);

	// Send IV, encrypted message, HMAC, and sequence
	size_t totalLength = sizeof(ivBuffer) + encryptedLength + sizeof(mac) + sizeof(transmittedSequence);
	unsigned char *packet = malloc(totalLength);
	if (!packet)
	{
		perror("Failed to allocate packet memory");
		return;
	}

	memcpy(packet, &transmittedSequence, sizeof(transmittedSequence));
	memcpy(packet + sizeof(transmittedSequence), ivBuffer, sizeof(ivBuffer));
	memcpy(packet + sizeof(transmittedSequence) + sizeof(ivBuffer), encryptedMessage, encryptedLength);
	memcpy(packet + sizeof(transmittedSequence) + sizeof(ivBuffer) + encryptedLength, mac, sizeof(mac));

	ssize_t nbytes = send(socketFD, packet, totalLength, 0);
	if (nbytes == -1)
	{
		perror("send failed");
	}

	free(packet);
	appendToTranscript(userMessage, NULL, 1);
	free(userMessage);

	// Clear message text and reset focus
	gtk_text_buffer_delete(messageBuffer, &startIter, &endIter);
	gtk_widget_grab_focus(messageWidget);

	// Increment sequence number after sending
	transmittedSequence++;
}

static gboolean displayNewMessage(gpointer msg)
{
	char *messageTags[2] = {"friend", NULL};
	char *friendName = "mr. friend: ";
	appendToTranscript(friendName, messageTags, 0);
	char *message = (char *)msg;
	appendToTranscript(message, NULL, 1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (initialize("params") != 0)
	{
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option longOpts[] = {
		{"connect", required_argument, 0, 'c'},
		{"listen", no_argument, 0, 'l'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};
	// process options:
	char c;
	int optIndex = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX + 1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", longOpts, &optIndex)) != -1)
	{
		switch (c)
		{
		case 'c':
			if (strnlen(optarg, HOST_NAME_MAX))
				strncpy(hostname, optarg, HOST_NAME_MAX);
			break;
		case 'l':
			isClient = 0;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			printf(usage, argv[0]);
			return 0;
		case '?':
			printf(usage, argv[0]);
			return 1;
		}
	}

	// initialize HMAC and AES
	static const unsigned char encryptionKeyArray[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	memcpy(encryptionKey, encryptionKeyArray, sizeof(encryptionKey));

	unsigned char staticAuthKey[64] = {
		0xbe, 0x41, 0x62, 0x1e, 0xa9, 0xf9, 0xef, 0x7b,
		0x6a, 0x2b, 0xab, 0x5a, 0xe3, 0xe6, 0x2d, 0xa2,
		0xf9, 0xcc, 0xff, 0x3c, 0x76, 0x20, 0xce, 0x63,
		0x35, 0xff, 0x9c, 0x0e, 0xed, 0x79, 0xa4, 0xba,
		0xbe, 0x41, 0x62, 0x1e, 0xa9, 0xf9, 0xef, 0x7b,
		0x6a, 0x2b, 0xab, 0x5a, 0xe3, 0xe6, 0x2d, 0xa2,
		0xf9, 0xcc, 0xff, 0x3c, 0x76, 0x20, 0xce, 0x63,
		0x35, 0xff, 0x9c, 0x0e, 0xed, 0x79, 0xa4, 0xba};
	memcpy(authKey, staticAuthKey, sizeof(authKey));

	if (isClient)
	{
		// generate client RSA keys
		generateRSACredentials("client_private.pem", "client_public.pem");
		printf("Client RSA keys generated successfully.\n");

		initializeClientNetwork(hostname, port);
	}
	else
	{
		// generate server RSA keys
		generateRSACredentials("server_private.pem", "server_public.pem");
		printf("Server RSA keys generated successfully.\n");

		initializeServerNetwork(port);
	}

	/* setup GTK... */
	GtkBuilder *builder;
	GObject *window;
	GObject *button;
	GObject *transcript;
	GObject *message;
	GError *error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder, "layout.ui", &error) == 0)
	{
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	textMark = gtk_text_mark_new(NULL, TRUE);
	window = gtk_builder_get_object(builder, "window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	textView = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	transcriptBuffer = gtk_text_view_get_buffer(textView);
	messageBuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(transmitMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));

	/* start receiver thread: */
	if (pthread_create(&receiveThread, 0, receiveMessage, 0))
	{
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	terminateNetwork();
	return 0;
}

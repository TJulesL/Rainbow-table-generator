#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <time.h>

#define MAX_LINE_LENGTH 256
#define BATCH_SIZE 6000  // Number of lines to process in each batch for performance



// get accurate time
double get_current_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); // Using CLOCK_MONOTONIC for a non-adjustable clock
    return (ts.tv_sec + ts.tv_nsec) / 1.0e9; // Convert to seconds with nanosecond precision
}

// Function to compute a hash using OpenSSL EVP API
void compute_hash(const char *input, unsigned char *output, const EVP_MD *md) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error creating EVP context\n");
        exit(1);
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        fprintf(stderr, "Error initializing EVP digest\n");
        exit(1);
    }

    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1) {
        fprintf(stderr, "Error updating EVP digest\n");
        exit(1);
    }

    if (EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
        fprintf(stderr, "Error finalizing EVP digest\n");
        exit(1);
    }

    EVP_MD_CTX_free(ctx);
}

// Function to convert a hash to a hex string
void hash_to_hex(unsigned char *hash, char *output, size_t length) {
    for (size_t i = 0; i < length; i++) {
        sprintf(&output[i * 2], "%02x", hash[i]);
    }
}

// Function to insert a hash batch into the SQLite database
void insert_hash_batch(sqlite3 *db, char hashes[][EVP_MAX_MD_SIZE * 2 + 1], char words[][MAX_LINE_LENGTH], int count) {
    const char *sql = "INSERT OR IGNORE INTO hashes (word, hash) VALUES (?, ?);";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    for (int i = 0; i < count; i++) {
        sqlite3_bind_text(stmt, 1, words[i], -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hashes[i], -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            printf("Failed to insert hash: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);
}

// Function to create a table in the SQLite database if it doesn't exist
void create_table(sqlite3 *db) {
    const char *sql = "CREATE TABLE IF NOT EXISTS hashes (id INTEGER PRIMARY KEY, word TEXT UNIQUE, hash TEXT);";
    char *err_msg = 0;
    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        printf("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <wordlist.txt>\n", argv[0]);
        return 1;
    }

    const char *wordlist_file = argv[1];
    FILE *wordlist = fopen(wordlist_file, "r");
    if (wordlist == NULL) {
        perror("Error opening wordlist file");
        return 1;
    }

    // Open SQLite databases for each hash algorithm
    sqlite3 *md5_db, *sha1_db, *sha256_db, *sha512_db;
    sqlite3_open("md5.db", &md5_db);
    sqlite3_open("sha1.db", &sha1_db);
    sqlite3_open("sha256.db", &sha256_db);
    sqlite3_open("sha512.db", &sha512_db);

    // Create tables if they do not exist
    create_table(md5_db);
    create_table(sha1_db);
    create_table(sha256_db);
    create_table(sha512_db);

    char line[MAX_LINE_LENGTH];
    char words[BATCH_SIZE][MAX_LINE_LENGTH];
    char md5_hex[BATCH_SIZE][EVP_MAX_MD_SIZE * 2 + 1];
    char sha1_hex[BATCH_SIZE][EVP_MAX_MD_SIZE * 2 + 1];
    char sha256_hex[BATCH_SIZE][EVP_MAX_MD_SIZE * 2 + 1];
    char sha512_hex[BATCH_SIZE][EVP_MAX_MD_SIZE * 2 + 1];

    // Define the hash algorithms using the EVP API
    const EVP_MD *md5 = EVP_md5();
    const EVP_MD *sha1 = EVP_sha1();
    const EVP_MD *sha256 = EVP_sha256();
    const EVP_MD *sha512 = EVP_sha512();

    int batch_count = 0;
	double batch_start = get_current_time();
	
    while (fgets(line, sizeof(line), wordlist)) {
        // Remove newline character
        line[strcspn(line, "\n")] = '\0';

        strncpy(words[batch_count], line, MAX_LINE_LENGTH);

        unsigned char hash_md5[EVP_MAX_MD_SIZE];
        unsigned char hash_sha1[EVP_MAX_MD_SIZE];
        unsigned char hash_sha256[EVP_MAX_MD_SIZE];
        unsigned char hash_sha512[EVP_MAX_MD_SIZE];

        // Hash the line once using each algorithm
        compute_hash(line, hash_md5, md5);
        char hash_md5_hex[EVP_MAX_MD_SIZE * 2 + 1];
        //hash_to_hex(hash_md5, hash_md5_hex, EVP_MD_size(md5));
        //compute_hash(hash_md5_hex, hash_md5, md5);
        hash_to_hex(hash_md5, md5_hex[batch_count], EVP_MD_size(md5));
        
        compute_hash(line, hash_sha1, sha1);
        char hash_sha1_hex[EVP_MAX_MD_SIZE * 2 + 1];
        //hash_to_hex(hash_sha1, hash_sha1_hex, EVP_MD_size(sha1));
        //compute_hash(hash_sha1_hex, hash_sha1, sha1);
        hash_to_hex(hash_sha1, sha1_hex[batch_count], EVP_MD_size(sha1));

  
        compute_hash(line, hash_sha256, sha256);
        char hash_sha256_hex[EVP_MAX_MD_SIZE * 2 + 1];
        //hash_to_hex(hash_sha256, hash_sha256_hex, EVP_MD_size(sha256));
        //compute_hash(hash_sha256_hex, hash_sha256, sha256);
        hash_to_hex(hash_sha256, sha256_hex[batch_count], EVP_MD_size(sha256));


        compute_hash(line, hash_sha512, sha512);
        char hash_sha512_hex[EVP_MAX_MD_SIZE * 2 + 1];
        //hash_to_hex(hash_sha512, hash_sha512_hex, EVP_MD_size(sha512));
        //compute_hash(hash_sha512_hex, hash_sha512, sha512);
        hash_to_hex(hash_sha512, sha512_hex[batch_count], EVP_MD_size(sha512));

        batch_count++;

        // If we've reached the batch size, insert into the database
        if (batch_count == BATCH_SIZE) {


            sqlite3_exec(md5_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
            sqlite3_exec(sha1_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
            sqlite3_exec(sha256_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
            sqlite3_exec(sha512_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

            insert_hash_batch(md5_db, md5_hex, words, batch_count);
            insert_hash_batch(sha1_db, sha1_hex, words, batch_count);
            insert_hash_batch(sha256_db, sha256_hex, words, batch_count);
            insert_hash_batch(sha512_db, sha512_hex, words, batch_count);

            sqlite3_exec(md5_db, "COMMIT;", NULL, NULL, NULL);
            sqlite3_exec(sha1_db, "COMMIT;", NULL, NULL, NULL);
            sqlite3_exec(sha256_db, "COMMIT;", NULL, NULL, NULL);
            sqlite3_exec(sha512_db, "COMMIT;", NULL, NULL, NULL);

            batch_count = 0;  // Reset batch count
			
			
            double batch_end = get_current_time();  // End time for batch processing
            printf("Batch inserted. Time taken: %.6f seconds.\n", batch_end - batch_start);
			double batch_start = get_current_time();
        }
    }

    fclose(wordlist);
    sqlite3_close(md5_db);
    sqlite3_close(sha1_db);
    sqlite3_close(sha256_db);
    sqlite3_close(sha512_db);

    return 0;
}

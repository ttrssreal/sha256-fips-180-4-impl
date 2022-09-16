void usage(char* run);
void print_digest(uint32_t* digest);

uint32_t* sha256hash(char* rawM);

static inline uint32_t ROTR(uint32_t x, int n);

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

static inline uint32_t cap_sigma0(uint32_t x);
static inline uint32_t cap_sigma1(uint32_t x);
static inline uint32_t sigma0(uint32_t x);
static inline uint32_t sigma1(uint32_t x);
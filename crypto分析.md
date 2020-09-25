# crypto分析

​	当上层想调用算法cbc（aes）对数据进行加解密。必须先申请一个tfm对其操作。其函数接口为crypto_alloc_skcipher（）。

![image-20200925134140441](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925134140441.png)

skcipher tfm申请调用接口如下：

```c
crypto_alloc_skcipher

——>crypto_alloc_tfm
	——>crypto_find_alg
    ——>crypto_create_tfm
```

* 系统先要通过crypto_find_alg函数到crypto_alg_list链表查找算法，如果不存在，则尝试加载一个算法。

* 当获得到所需要的算法后，就会为该算法申请tfm。tfm是上层对算法操作的对象。



## 动态算法注册

![image-20200925135304046](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925135304046.png)

​	crypto_find_alg会获得所要查找算法的名称，然后通过遍历crypto_allg_list查找该算法，如果存在，则直接返回该算法。如果不存在，系统会为该算法创建同名的算法幼虫，该算法幼虫主要用于注册。在动态算法注册过程中还有一个算法幼虫，成为检测用算法幼虫，用于检测。算法注册完成需要进行自检。下文会有说明。

### 1.动态算法注册通知发布

​	对于动态算法来说，添加完注册用算法幼虫只是第一步，下一步是在加密通知链上发布注册并注册动态算法通知（CRYPTO_MSG_ALG_REQUEST）。

![image-20200925145511236](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925145511236.png)

```c
struct crypto_alg *crypto_alg_mod_lookup(const char *name, u32 type, u32 mask)
{
	...
    larval = crypto_larval_lookup(name, type, mask);//算法查找，
    ...
        
	ok = crypto_probing_notify(CRYPTO_MSG_ALG_REQUEST, larval);//在加密通知链发布创建动态算法。调用内核线程创建并注册算法
	...
	return alg;
}
```



​	加密通知链回调函数cryptomgr_notify根据通知消息类型msg调用不同的执行函数，如下所示。

```c
static int cryptomgr_notify(struct notifier_block *this, unsigned long msg,void *data)
{
	switch (msg) {
	case CRYPTO_MSG_ALG_REQUEST:
		return cryptomgr_schedule_probe(data);
	case CRYPTO_MSG_ALG_REGISTER:
		return cryptomgr_schedule_test(data);
	}

	return NOTIFY_DONE;
}
```

```c
static int cryptomgr_schedule_probe(struct crypto_larval *larval)//算法探测，larval注册用算法幼虫
{
    ...
    struct cryptomgr_param *param;
	thread = kthread_run(cryptomgr_probe, param, "cryptomgr_probe");//创建动态算法
	...
}
```



​	cryptomgr_schedule_probe函数参数为注册用算法幼虫，该函数会从注册用算法幼虫解析出算法模板名和基础算法名并填充至结构体cryptomgr_param。然后将此结构体当作函数参数传递给线程cryptomgr_probe。

```c
static int cryptomgr_probe(void *data)
{
	....
	tmpl = crypto_lookup_template(param->template);//模板查找
	do {
		if (tmpl->create) {
			err = tmpl->create(tmpl, param->tb);//算法模板实例创建
			continue;
		}

		inst = tmpl->alloc(param->tb);
		if (IS_ERR(inst))
			err = PTR_ERR(inst);
		else if ((err =    (tmpl, inst)))
			tmpl->free(inst);
	} while (err == -EAGAIN && !signal_pending(current));
    ...
}
```

​	

​	cryptomgr_probe用于触发模板的create函数，该函数会为该算法创建并注册一个算法模板实例(instance)。在创建instance时会创建skcipher_alg，skcipher_alg便是要申请注册的动态算法。如下是算法模板实例的结构体（对于cbc来说，它的instance是skcipher_instance）：

```c
struct skcipher_instance {
	void (*free)(struct skcipher_instance *inst);
	union {
		struct {
			char head[offsetof(struct skcipher_alg, base)];
			struct crypto_instance base;
		} s;
		struct skcipher_alg alg;
	};
};
```


### 2.创建算法模板实例（instance）

​	算法模板实例创建如下：

![image-20200925145603844](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925145603844.png)

算法模板实例的创建时为了为算法创建属于它的crypto_alg,以及spawn，spawn的作用是为子算法孵化出一个tfm，cbc（aes），aes就为子算法。

为instance申请空间的同时，也为spawn申请空间。因为地址的连续性可以更好的访问spawn。

instance结构体下的crypto_alg就是要注册的算法。

```c
static int crypto_cbc_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	...

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);//创建算法模板实例（skcipher_instance），crypto_instance结构的最后一个成员ctx是一个指针变量，所以，在分配空间的时候，在其尾部追加相应的空间，可以使用ctx访问之（spawn）。

	alg = crypto_get_attr_alg(tb, CRYPTO_ALG_TYPE_CIPHER, mask);//获取基础算法

	spawn = skcipher_instance_ctx(inst);//通过instance创建spawn，spawn和instance的关系是通过instance的_ctx来联系。

	err = crypto_inst_setname(skcipher_crypto_instance(inst), "cbc", alg);//设置算法名称与驱动名称。

	inst->alg.base.cra_priority = alg->cra_priority;//inst初始化，将基础算法的属性赋值给动态生成的算法，往下都是。
	inst->alg.base.cra_blocksize = alg->cra_blocksize;
	inst->alg.base.cra_alignmask = alg->cra_alignmask;

	inst->alg.ivsize = alg->cra_blocksize;
	inst->alg.min_keysize = alg->cra_cipher.cia_min_keysize;
	inst->alg.max_keysize = alg->cra_cipher.cia_max_keysize;

	inst->alg.base.cra_ctxsize = sizeof(struct crypto_cbc_ctx);//实际上是tfm大小

	inst->alg.init = crypto_cbc_init_tfm;//spawn孵化
	inst->alg.exit = crypto_cbc_exit_tfm;

	//动态算法的密钥设置和加解密函数。
	inst->alg.setkey = crypto_cbc_setkey;
	inst->alg.encrypt = crypto_cbc_encrypt;
	inst->alg.decrypt = crypto_cbc_decrypt;

	inst->free = crypto_cbc_free;

	err = skcipher_register_instance(tmpl, inst);//算法模板实例注册。

	crypto_mod_put(alg);//释放算法引用计数，
    
    ...
}
```



### 3.算法模板实例注册

​	instance流程图如下：

![image-20200925151819546](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925151819546.png)

* 算法注册由通用算法注册函数__crypto_register_alg完成，输入参数为算法模板实例对应的通用  算法说明inst->alg，返回值为检测用算法幼虫larval。
* 将算法模板实例添加到算法模板的实例链表中，同时设置算法模板实例归属的算法模板。
* 和静态算法相同，动态算法注册的最后一步是算法正确性检验，调用crypto_wait_for_test函数实现。

部分代码实现如下：

```c
int crypto_register_instance(struct crypto_template *tmpl,struct crypto_instance *inst)
{
    ...
	struct crypto_larval *larval;//算法幼虫

	err = crypto_check_alg(&inst->alg);//算法有效性检查

	larval = __crypto_register_alg(&inst->alg);//算法注册

	hlist_add_head(&inst->list, &tmpl->instances);//将instance加入的到模板算法实例链表

	crypto_wait_for_test(larval);//算法自检
	...
}
```

至此，算法的注册已经算是完成了。如果需要使用该算法，还需要tfm。



## 静态算法注册

​        静态算法与动态算法相比，静态算法在内核是实实在在的以***.ko的形式存在。而动态算法不同，动态算法是静态算法的衍生。它是在静态算法的外层套上一层模板，例如cbc（aes），cbc就是模板。因此，静态算法的注册会与动态算法的注册有很大的不同，静态算法只需要调用函数crypto_register_alg进行注册就可以了。

crypto_register_alg的流程图如下：

![image-20200925153622872](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925153622872.png)

静态算法的注册主要工作在函数__crypto_register_alg。它要对算法进行检测，包括类型检测，状态检测。然后从crypto_alg_list链表查找存在该算法，如果存在，检测该算法是否是算法幼虫，如果是，说明该算法正在注册。返回等待算法注册完成，然后普进行检验。如果不是则说明该算法已存在。如果算法不存在，则在crypto_alg_list注册一个检测用算法幼虫。检测用算法幼虫是用来在算法注册完成后进行检验的。

__crypto_register_alg的流程图如下：



![image-20200925154612846](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925154612846.png)



## tfm初始化和分配

​	算法注册完成后，从crypto_alg_list找到算法。然后为该算法分配一个tfm，这样，上层可以通过tfm操作该算法进行加解密了。

​	tfm申请流程如下：

![image-20200925154902074](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925154902074.png)

* tfm结构体申请空间。

* 初始化tfm的选项，以cbc（aes）为例；

* tfm初始化（spawn孵化）。

  


### 1.tfm选项初始化

![image-20200925164450348](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925164450348.png)

```c
void *crypto_create_tfm(struct crypto_alg *alg,const struct crypto_type *frontend)
{
	...

	tfm = (struct crypto_tfm *)(mem + tfmsize);//tfm分配
	tfm->__crt_alg = alg;//__crt_alg成员指向其所属的算法，对于cbc而言，它就是cbc(xxx)，例如cbc(aes)

	err = frontend->init_tfm(tfm);//初始化tfm选项。对于crypto_skcipher_type2来说就是crypto_skcipher_init_tfm

	if (!tfm->exit && alg->cra_init && (err = alg->cra_init(tfm)))//tfm的初始化。spawn孵化
		goto cra_init_failed;

	...
}
```

skcipher的crypto_type为crypto_skcipher_type2，所以它的tfm选项初始化应当是crypto_skcipher_init_tfm；tfm根据方式的不同调用不同函数初始化。

```c
static int crypto_skcipher_init_tfm(struct crypto_tfm *tfm)//skcipher tfm的初始化
{
	struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);//将tfm转换成skcipher类型
	struct skcipher_alg *alg = crypto_skcipher_alg(skcipher);//取得alg

	if (tfm->__crt_alg->cra_type == &crypto_blkcipher_type)//同步
		return crypto_init_skcipher_ops_blkcipher(tfm);

	if (tfm->__crt_alg->cra_type == &crypto_ablkcipher_type ||//异步
	    tfm->__crt_alg->cra_type == &crypto_givcipher_type)
		return crypto_init_skcipher_ops_ablkcipher(tfm);

	skcipher->setkey = skcipher_setkey;
	skcipher->encrypt = alg->encrypt;
	skcipher->decrypt = alg->decrypt;
	skcipher->ivsize = alg->ivsize;
	skcipher->keysize = alg->max_keysize;

	skcipher_set_needkey(skcipher);

	if (alg->exit)
		skcipher->base.exit = crypto_skcipher_exit_tfm;

	if (alg->init)
		return alg->init(skcipher);

	return 0;
}
```

这里以同步方式进行举例：

```c
static int crypto_init_skcipher_ops_blkcipher(struct crypto_tfm *tfm)
{
	struct crypto_alg *calg = tfm->__crt_alg;//对于cbc（aes），就是cbc（aes）的crypto_alg
	struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);//将tfm转化成skcipher的tfm
	struct crypto_blkcipher **ctx = crypto_tfm_ctx(tfm);//获取上下文（前面分配tfm）
	struct crypto_blkcipher *blkcipher;
	struct crypto_tfm *btfm;

	if (!crypto_mod_get(calg))
		return -EAGAIN;

	btfm = __crypto_alloc_tfm(calg, CRYPTO_ALG_TYPE_BLKCIPHER,//再分配一个tfm，用于设置tfm的__crt_ctx成员
					CRYPTO_ALG_TYPE_MASK);
	if (IS_ERR(btfm)) {
		crypto_mod_put(calg);
		return PTR_ERR(btfm);
	}

	blkcipher = __crypto_blkcipher_cast(btfm);//指向分配到的tfm。即blkcipher=btfm
	*ctx = blkcipher;
	tfm->exit = crypto_exit_skcipher_ops_blkcipher;
	
	skcipher->setkey = skcipher_setkey_blkcipher;
	skcipher->encrypt = skcipher_encrypt_blkcipher;
	skcipher->decrypt = skcipher_decrypt_blkcipher;

	skcipher->ivsize = crypto_blkcipher_ivsize(blkcipher);
	skcipher->keysize = calg->cra_blkcipher.max_keysize;

	skcipher_set_needkey(skcipher);

	return 0;
}
```



### 2. tfm初始化

在cbc的create的create函数已经为cbc（aes）创建了一个spawn，现在只需要对它进行初始化，就可以诞生cbc（aes）这个算法了。过程可以理解为先生蛋，再孵化。

流程如下：

![image-20200925165353193](C:\Users\lenovo.DESKTOP-JAA702O\AppData\Roaming\Typora\typora-user-images\image-20200925165353193.png)

具体代码如下：

```c
static int crypto_cbc_init_tfm(struct crypto_skcipher *tfm)
{
	struct skcipher_instance *inst = skcipher_alg_instance(tfm);
	struct crypto_spawn *spawn = skcipher_instance_ctx(inst);
	struct crypto_cbc_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct crypto_cipher *cipher;

	cipher = crypto_spawn_cipher(spawn); //对cbc(aes)进行孵化，以cbc(aes)为例，这将得到一个aes算法的tfm
		return PTR_ERR(cipher);

	ctx->child = cipher;//设置子算法的tfm
	return 0;
}

```



## 算法检验

​	算法注册完成后，会唤醒函数crypto_wait_for_test对算法的检验。

**待补充** 
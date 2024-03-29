# 链表  

## 单链表  

定义一个单链表：
madlloc会在堆内存申请一块空间，使用之后必须使用free释放  

```C  
typedef struct LNode{               //定义结点类型
    ElemType Data;          //定义数据域
    LNode* Next;    //结点指针指向下一结点

}LNode
```  

### 插入  

按位序插入（带头节点）：  

```C
bool ListInsert(LNode *L,int i,ElemType e){//在L链表的i位置插入任意类型e数据
    if(i<1)             //带头结点默认头节点是0位置，
        return false;
    LNode* p;
    p=L;                //p指向L的头节点
    int j=0;              //j用来判断p指针指向的位置
    while(p!==NULL && j<i-1){//循环找到i-1的结点位置
        p=p->next;
        j++;
    }
    if(p==NULL)             //当插入的位置大于了链表长度，在上面循环p为null就退出，然后执行这个判断。
        return false;
    LNode* s=(LNode *)malloc(sizeof(ElemType)) //给s结点分配空间，我们注意到malloc函数中没有乘以LNode，这代表这里是给单个结点分配空间
    s->data=e;
    s->next=p->next; //将s连在i-1的位置之后，并且下面这两条语句不能调换
    p->next=s;
    return true;
}
```  

按位序插入（不带头节点）：  

```C
bool ListInsert(LNode *L,int i,ElemType e){//在L链表的i位置插入任意类型e数据
    if(i<1)             //带头结点默认头节点是0位置，
        return false;
    if(i==1){
        LNode* s=(LNode *)malloc(sizeof(ElemType))
        s->data=e;
        s->next=L;
        L=s;
        return ture;
    }
    LNode* p;
    p=L;                
    int j=1;              //和上边不一样，需要注意
    while(p!==NULL && j<i-1){ //后面代码都一样
        p=p->next;
        j++;
    }
    if(p==NULL)             
        return false;
    LNode* s=(LNode *)malloc(sizeof(ElemType)) 
    s->data=e;
    s->next=p->next; 
    p->next=s;
    return true;
}
```  

后插操作：在p结点后面插入e

```C
bool InsertNext(LNode* p,ElemType e){
        if(p==NULL)             
            return false;
        LNode* s=(LNode *)malloc(sizeof(ElemType)) 
        if(s==NULL)
            return false; //分配内存空间失败
        s->data=e;
        s->next=p->next; 
        p->next=s;
        return true;
}

```  

前插操作：在p结点前面插入e

```C
bool InsertPrior(LNode* p,ElemType e){
        if(p==NULL)             
            return false;
        LNode* s=(LNode *)malloc(sizeof(ElemType)) 
        if(s==NULL)
            return false; //分配内存空间失败
        s->next=p->next; 
        p->next=s;
        s->data=p->data;
        p->data=e;
        return true;
}

```  

### 删除  

按位序删除（带头节点）：  

```C
bool ListDelete(LNode *L,int i,ElemType &e){ //这里e需要返回给调用函数那里
    if(i<1)             
        return false;
    LNode* p;
    p=L;                
    int j=0;             
    while(p!==NULL && j<i-1){
        p=p->next;
        j++;
    }
    if(p==NULL)             
        return false;
    if(p->next==NULL)
        return false;       //p后无结点
    LNode *q=p->next;       //q指向将要删除的结点
    e=q->data;              //用e返回元素值
    p->next=q->next;        //然后将p和q断开
    free(q);                //释放p结点
    return true;
}
```  

删除指定结点p(带头)  

```C
bool DeleteNode(LNode *p){
    if(p==NULL)
        return false;
    LNode *q=p->next;          //q指向p下一个结点
    p->data=p->next->data;      //将p下一个结点的值赋给p结点
    p->next=q->next;        //将q结点断开
    free(q);                //释放q，这样做是因为不知道p前一个结点，所以没法直接删除p结点，但有一个bug，就是如果p下一个结点为空就报错，这时就必须从头节点开始找/
    return ture;
}
```  

### 查找  

按位查找（带头）  

```C
LNode * GetElem(LNode *L,int i){
    if(i<0)
        return NULL;
    LNode *p;
    int j=0;
    p=L;        //p指向头节点，0位置
    while(p!=NULL && j<i){
        p=p->next;
        j++;
    }
    return p;//返回p，如果p指向了NULL，上面i<0也为NULL，则可以判断查找成功与失败
}
```  

按值查找（带头）  

```C
LNode * LocateElem(LNode *p,Elemtype e){//如果ElemType位struct则不能用!=判断不等
    LNode *p=p->next;
    while(p!=NULL && p->data!=e){
        p=p->next;
    }
    return p;
}
```  

### 建立单链表  

尾插法  

```C
LNode * List_TailInsert(LNode *L){
    int x;
    L=(LNode*)malloc(sizeof(LNode))
    LNode *s,*r=L;          //s和r指针都从L链表头开始
    scanf("%d",&x);         //x为我们输入的值
    while(x!=9999){         //9999判断是否结束插入
        s=(LNode*)malloc(sizeof(LNode));    //分配一个结点
        s->data=x;                          //给结点存入数据
        r->next=s;                          //将r指向的L头指向s结点
        r=s;                                //r指向新的表尾
        scanf("%d",&x);
    }
    r->next=NULL;//最后r指向NULL
    return L;
}
```  

头插法，输入的结果顺序在链表中存储顺序是逆置的  

```C
LNode * List_HeadInsert(LNode *L){
    int x;
    L=(LNode*)malloc(sizeof(LNode))
    L->next=NULL;                       //初始化空链表，防止脏数据
    LNode *s;          
    scanf("%d",&x);         
    while(x!=9999){         
        s=(LNode*)malloc(sizeof(LNode));    
        s->data=x;                          
        s->next=L->next;                          
        L->next=s;                                
        scanf("%d",&x);
    }
    return L;
}
```

## 双链表  

定义  

```C
typedef struct DNode{
    ElemType data;
    DNode *prior,*next;//定义前指针，后指针
}DNode
```

在p结点后面插入s结点

```C
bool InsertDNode(DNode *p,DNode *s){//双链表指针定义
    if(p==NULL && s==NULL)
        return false;
    s->next=p->next;
    if(p->next!=NULL)       //当p为最后一个结点时，指向NULL，防止空指针错误
        p->next->prior=s;
    s->prior=p;             //指针指向顺序都是从s开始指向其他
    p->next=s;
    return true;
}
```  

删除p结点之后的结点  

```C
bool DeldeteDNode(DNode *p){
    if(p==NULL)
        return false;
    DNode *q=p->next;
    if(q==NULL) return false;       //到这里我发现每个指针都要判断是否为空
    p->next=q->next;
    if(q->next!=NULL)
        q->next->prior=p;
    free(q);
    return true;
}
```  

## 循环链表  


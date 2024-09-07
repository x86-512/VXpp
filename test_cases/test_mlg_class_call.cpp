class A{
    public:
    int counter;
    A() {
        counter = 0;
    }
    virtual void ink() {
        counter++;
    }
    virtual void dek() {
        counter--;
    }
    virtual void dekx(int x, int y, int z, int al, int be) {
        counter-=x;
        counter-=y;
        counter-=z;
        counter-=al;
        counter-=be;
    }
};

class B{
    public:
    int data = 0;
    A *subclass[3];
    B() {
        for(int i= 0;i<3; i++) {
            subclass[i] = new A();
        }
    }
    virtual void incA() {
        for(int i= 0;i<3; i++) {
            subclass[i]->dek();
        }
    }
    virtual void incAx(int x) {
        for(int i= 0;i<3; i++) {
            subclass[i]->dekx(i, x, 3, 2, 1);
        }
    }
};

int main() {
    B *b = new B();
    b->incA();
    int x = 5;
    b->incAx(x);
    return 0;
}
